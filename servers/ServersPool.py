from threading import Thread
import ssl
import struct
from utils import *
from SocketServer import TCPServer, UDPServer, ThreadingMixIn

class ThreadingUDPServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To + '\0')
            except:
                pass
        UDPServer.server_bind(self)


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To + '\0')
            except:
                pass
        TCPServer.server_bind(self)


class ThreadingTCPServerAuth(ThreadingMixIn, TCPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To + '\0')
            except:
                pass
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        TCPServer.server_bind(self)


class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        MADDR = "224.0.0.251"

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        Join = self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                      socket.inet_aton(MADDR) + settings.Config.IP_aton)

        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To + '\0')
            except:
                pass
        UDPServer.server_bind(self)


class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        MADDR = "224.0.0.252"

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        Join = self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                      socket.inet_aton(MADDR) + settings.Config.IP_aton)

        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To + '\0')
            except:
                pass
        UDPServer.server_bind(self)


ThreadingUDPServer.allow_reuse_address = 1
ThreadingTCPServer.allow_reuse_address = 1
ThreadingUDPMDNSServer.allow_reuse_address = 1
ThreadingUDPLLMNRServer.allow_reuse_address = 1
ThreadingTCPServerAuth.allow_reuse_address = 1


def serve_thread_udp_broadcast(host, port, handler):
    try:
        server = ThreadingUDPServer(('', port), handler)
        server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting UDP server on port " + str(
            port) + ", check permissions or other servers running."


def serve_NBTNS_poisoner(host, port, handler):
    serve_thread_udp_broadcast(host, port, handler)


def serve_MDNS_poisoner(host, port, handler):
    try:
        server = ThreadingUDPMDNSServer((host, port), handler)
        server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting UDP server on port " + str(
            port) + ", check permissions or other servers running."


def serve_LLMNR_poisoner(host, port, handler):
    try:
        server = ThreadingUDPLLMNRServer((host, port), handler)
        server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting UDP server on port " + str(
            port) + ", check permissions or other servers running."


def serve_thread_udp(host, port, handler):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingUDPServer((settings.Config.Bind_To, port), handler)
            server.serve_forever()
        else:
            server = ThreadingUDPServer((host, port), handler)
            server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting UDP server on port " + str(
            port) + ", check permissions or other servers running."


def serve_thread_tcp(host, port, handler):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingTCPServer((settings.Config.Bind_To, port), handler)
            server.serve_forever()
        else:
            server = ThreadingTCPServer((host, port), handler)
            server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting TCP server on port " + str(
            port) + ", check permissions or other servers running."


def serve_thread_tcp_auth(host, port, handler):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingTCPServerAuth((settings.Config.Bind_To, port), handler)
            server.serve_forever()
        else:
            server = ThreadingTCPServerAuth((host, port), handler)
            server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting TCP server on port " + str(
            port) + ", check permissions or other servers running."


def serve_thread_SSL(host, port, handler):
    try:

        cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
        key = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)

        if OsInterfaceIsSupported():
            server = ThreadingTCPServer((settings.Config.Bind_To, port), handler)
            server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
            server.serve_forever()
        else:
            server = ThreadingTCPServer((host, port), handler)
            server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
            server.serve_forever()
    except:
        print color("[!] ", 1, 1) + "Error starting SSL server on port " + str(
            port) + ", check permissions or other servers running."


class ServersPool:
    """ServersPool provides managing of the threads according current settings."""
    def __init__(self, settings):
        self.__threadsPool = []
        self.__settings = settings
        self.initServers()

    def start(self):
        for thread in self.__threadsPool:
            thread.setDaemon(True)
            thread.start()

    def initServers(self):
        # Load (M)DNS, NBNS and LLMNR Poisoners
        from poisoners.LLMNR import LLMNR
        from poisoners.NBTNS import NBTNS
        from poisoners.MDNS import MDNS
        self.__threadsPool.append(Thread(target=serve_MDNS_poisoner, args=('', 5353, MDNS,)))
        self.__threadsPool.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR,)))
        self.__threadsPool.append(Thread(target=serve_NBTNS_poisoner, args=('', 137, NBTNS,)))

        # Load Browser Listener
        from servers.Browser import Browser
        self.__threadsPool.append(Thread(target=serve_thread_udp_broadcast, args=('', 138, Browser,)))

        if settings.Config.HTTP_On_Off:
            from servers.HTTP import HTTP
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 80, HTTP,)))

        if settings.Config.SSL_On_Off:
            from servers.HTTP import HTTPS
            self.__threadsPool.append(Thread(target=serve_thread_SSL, args=('', 443, HTTPS,)))

        if settings.Config.WPAD_On_Off:
            from servers.HTTP_Proxy import HTTP_Proxy
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 3141, HTTP_Proxy,)))

        if settings.Config.ProxyAuth_On_Off:
            from servers.Proxy_Auth import Proxy_Auth
            self.__threadsPool.append(Thread(target=serve_thread_tcp_auth, args=('', 3128, Proxy_Auth,)))

        if settings.Config.SMB_On_Off:
            if settings.Config.LM_On_Off:
                from servers.SMB import SMB1LM
                self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 445, SMB1LM,)))
                self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 139, SMB1LM,)))
            else:
                from servers.SMB import SMB1
                self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 445, SMB1,)))
                self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 139, SMB1,)))

        if settings.Config.Krb_On_Off:
            from servers.Kerberos import KerbTCP, KerbUDP
            self.__threadsPool.append(Thread(target=serve_thread_udp, args=('', 88, KerbUDP,)))
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 88, KerbTCP,)))

        if settings.Config.SQL_On_Off:
            from servers.MSSQL import MSSQL
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 1433, MSSQL,)))

        if settings.Config.FTP_On_Off:
            from servers.FTP import FTP
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 21, FTP,)))

        if settings.Config.POP_On_Off:
            from servers.POP3 import POP3
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 110, POP3,)))

        if settings.Config.LDAP_On_Off:
            from servers.LDAP import LDAP
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 389, LDAP,)))

        if settings.Config.SMTP_On_Off:
            from servers.SMTP import ESMTP
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 25, ESMTP,)))
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 587, ESMTP,)))

        if settings.Config.IMAP_On_Off:
            from servers.IMAP import IMAP
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 143, IMAP,)))

        if settings.Config.DNS_On_Off:
            from servers.DNS import DNS, DNSTCP
            self.__threadsPool.append(Thread(target=serve_thread_udp, args=('', 53, DNS,)))
            self.__threadsPool.append(Thread(target=serve_thread_tcp, args=('', 53, DNSTCP,)))
