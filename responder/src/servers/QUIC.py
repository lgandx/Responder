import asyncio
import logging
import ssl
import argparse
import netifaces
from responder.src.utils import *
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    QuicEvent,
    StreamDataReceived,
    StreamReset,
    ConnectionTerminated,
)

BUFFER_SIZE = 11000


def get_interface_ip(interface_name):
    """Get the IP address of a network interface."""
    try:
        # Get address info for the specified interface
        addresses = netifaces.ifaddresses(interface_name)

        # Get IPv4 address (AF_INET = IPv4)
        if netifaces.AF_INET in addresses:
            return addresses[netifaces.AF_INET][0]["addr"]

        # If no IPv4 address, try IPv6 (AF_INET6 = IPv6)
        if netifaces.AF_INET6 in addresses:
            return addresses[netifaces.AF_INET6][0]["addr"]

        logging.error(f"[!] No IP address found for interface {interface_name}")
        return None
    except ValueError:
        logging.error(f"[!] Interface {interface_name} not found")
        return None


class QUIC(QuicConnectionProtocol):
    def __init__(self, *args, target_address=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tcp_connections = {}  # stream_id -> (reader, writer)
        self.target_address = target_address or "localhost"

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            asyncio.create_task(self.handle_stream_data(event.stream_id, event.data))
        elif isinstance(event, StreamReset) or isinstance(event, ConnectionTerminated):
            # Only try to close connections if we have any
            if self.tcp_connections:
                asyncio.create_task(self.close_all_tcp_connections())

    async def handle_stream_data(self, stream_id, data):
        if stream_id not in self.tcp_connections:
            # Create a new TCP connection to the target interface:445
            try:
                reader, writer = await asyncio.open_connection(self.target_address, 445)
                self.tcp_connections[stream_id] = (reader, writer)

                # Start task to read from TCP and write to QUIC
                asyncio.create_task(self.tcp_to_quic(stream_id, reader))

                logging.info(
                    f"[*] Connected to {self.target_address}:445\n[*] Starting relaying process..."
                )
                print(text("[QUIC] Forwarding QUIC connection to SMB server"))
            except Exception as e:
                logging.error(f"[!] Error connecting to {self.target_address}:445: {e}")
                return

        # Forward data from QUIC to TCP
        try:
            _, writer = self.tcp_connections[stream_id]
            writer.write(data)
            await writer.drain()
        except Exception as e:
            logging.error(f"[!] Error writing to TCP: {e}")
            await self.close_tcp_connection(stream_id)

    async def tcp_to_quic(self, stream_id, reader):
        try:
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break

                self._quic.send_stream_data(stream_id, data)
                self.transmit()
        except Exception as e:
            logging.error(f"[!] Error reading from TCP: {e}")
        finally:
            await self.close_tcp_connection(stream_id)

    async def close_tcp_connection(self, stream_id):
        if stream_id in self.tcp_connections:
            _, writer = self.tcp_connections[stream_id]
            writer.close()
            await writer.wait_closed()
            del self.tcp_connections[stream_id]

    async def close_all_tcp_connections(self):
        try:
            # Make a copy of the keys to avoid modification during iteration
            stream_ids = list(self.tcp_connections.keys())
            for stream_id in stream_ids:
                try:
                    await self.close_tcp_connection(stream_id)
                except KeyError:
                    # Silently ignore if the stream ID no longer exists
                    pass
        except Exception as e:
            # Catch any other exceptions that might occur
            logging.debug(f"[!] Error closing TCP connections: {e}")


async def start_quic_server(listen_interface, cert_path, key_path):
    # Configure QUIC
    configuration = QuicConfiguration(
        alpn_protocols=["smb"],
        is_client=False,
    )

    # Load certificate and private key
    try:
        configuration.load_cert_chain(cert_path, key_path)
    except Exception as e:
        logging.error(f"[!] Could not load {cert_path} and {key_path}: {e}")
        return

    # Resolve interfaces to IP addresses
    listen_ip = listen_interface
    if not is_ip_address(listen_interface):
        listen_ip = get_interface_ip(listen_interface)
        if not listen_ip:
            logging.error(
                f"[!] Could not resolve IP address for interface {listen_interface}"
            )
            return

    target_ip = listen_interface
    if not is_ip_address(listen_interface):
        target_ip = get_interface_ip(listen_interface)
        if not target_ip:
            logging.error(
                f"[!] Could not resolve IP address for interface {listen_interface}"
            )
            return

    # Start QUIC server with correct protocol factory
    server = await serve(
        host=listen_ip,
        port=443,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: QUIC(
            *args, target_address=target_ip, **kwargs
        ),
    )

    logging.info(f"[*] Started listening on {listen_ip}:443 (UDP)")
    logging.info(f"[*] Forwarding connections to {target_ip}:445 (TCP)")

    # Keep the server running forever
    await asyncio.Future()


def is_ip_address(address):
    """Check if a string is a valid IP address."""
    import socket

    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False
