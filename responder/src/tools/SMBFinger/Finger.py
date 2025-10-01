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
import re, sys, socket, struct
import multiprocessing
from socket import *
from time import sleep
from .odict import OrderedDict

__version__ = "0.7"

Timeout = 2


class Packet:
    fields = OrderedDict([])

    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k, v in list(kw.items()):
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v

    def __str__(self):
        return "".join(map(str, list(self.fields.values())))


# Python version
if sys.version_info > (3, 0):
    PY2OR3 = "PY3"
else:
    PY2OR3 = "PY2"

SMB1 = "Enabled"


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


def longueur(payload):
    length = StructWithLenPython2or3(">i", len("".join(payload)))
    return length


class SMBHeader(Packet):
    fields = OrderedDict(
        [
            ("proto", "\xff\x53\x4d\x42"),
            ("cmd", "\x72"),
            ("error-code", "\x00\x00\x00\x00"),
            ("flag1", "\x00"),
            ("flag2", "\x00\x00"),
            ("pidhigh", "\x00\x00"),
            ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("reserved", "\x00\x00"),
            ("tid", "\x00\x00"),
            ("pid", "\x00\x00"),
            ("uid", "\x00\x00"),
            ("mid", "\x00\x00"),
        ]
    )


class SMBNego(Packet):
    fields = OrderedDict([("Wordcount", "\x00"), ("Bcc", "\x62\x00"), ("Data", "")])

    def calculate(self):
        self.fields["Bcc"] = StructWithLenPython2or3(
            "<h", len(str(self.fields["Data"]))
        )


class SMBNegoData(Packet):
    fields = OrderedDict(
        [
            ("BuffType", "\x02"),
            ("Dialect", "NT LM 0.12\x00"),
        ]
    )


class SMBSessionFingerData(Packet):
    fields = OrderedDict(
        [
            ("wordcount", "\x0c"),
            ("AndXCommand", "\xff"),
            ("reserved", "\x00"),
            ("andxoffset", "\x00\x00"),
            ("maxbuff", "\x04\x11"),
            ("maxmpx", "\x32\x00"),
            ("vcnum", "\x00\x00"),
            ("sessionkey", "\x00\x00\x00\x00"),
            ("securitybloblength", "\x4a\x00"),
            ("reserved2", "\x00\x00\x00\x00"),
            ("capabilities", "\xd4\x00\x00\xa0"),
            ("bcc1", "\xb1\x00"),
            (
                "Data",
                "\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00",
            ),
        ]
    )


##Now Lanman
class SMBHeaderLanMan(Packet):
    fields = OrderedDict(
        [
            ("proto", "\xff\x53\x4d\x42"),
            ("cmd", "\x72"),
            ("error-code", "\x00\x00\x00\x00"),
            ("flag1", "\x08"),
            ("flag2", "\x01\xc8"),
            ("pidhigh", "\x00\x00"),
            ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("reserved", "\x00\x00"),
            ("tid", "\x00\x00"),
            ("pid", "\x3c\x1b"),
            ("uid", "\x00\x00"),
            ("mid", "\x00\x00"),
        ]
    )


# We grab the domain and hostname from the negotiate protocol answer, since it is in a Lanman dialect format.
class SMBNegoDataLanMan(Packet):
    fields = OrderedDict(
        [
            ("Wordcount", "\x00"),
            ("Bcc", "\x0c\x00"),
            ("BuffType", "\x02"),
            ("Dialect", "NT LM 0.12\x00"),
        ]
    )


#####################


def color(txt, code=1, modifier=0):
    return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)


def IsSigningEnabled(data):
    if data[39:40] == b"\x0f":
        return True
    else:
        return False


def atod(a):
    return struct.unpack("!L", inet_aton(a))[0]


def dtoa(d):
    return inet_ntoa(struct.pack("!L", d))


def GetBootTime(data):
    try:
        Filetime = int(struct.unpack("<q", data)[0])
        t = divmod(Filetime - 116444736000000000, 10000000)
        time = datetime.datetime.fromtimestamp(t[0])
        return time, time.strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass


def OsNameClientVersion(data):
    try:
        length = struct.unpack("<H", data[43:45].encode("latin-1"))[0]
        if length > 255:
            OsVersion, ClientVersion = tuple(
                [
                    e.replace("\x00", "")
                    for e in data[47 + length :].split("\x00\x00\x00")[:2]
                ]
            )
            return OsVersion, ClientVersion
        if length <= 255:
            OsVersion, ClientVersion = tuple(
                [
                    e.replace("\x00", "")
                    for e in data[46 + length :].split("\x00\x00\x00")[:2]
                ]
            )
            return OsVersion, ClientVersion
    except:
        return (
            "Could not fingerprint Os version.",
            "Could not fingerprint LanManager Client version",
        )


def GetHostnameAndDomainName(data):
    try:
        data = NetworkRecvBufferPython2or3(data)
        DomainJoined, Hostname = tuple(
            [e.replace("\x00", "") for e in data[81:].split("\x00\x00\x00")[:2]]
        )
        # If max length domain name, there won't be a \x00\x00\x00 delineator to split on
        if Hostname == "":
            DomainJoined = data[81:110].decode("latin-1")
            Hostname = data[113:].decode("latin-1")
        return Hostname, DomainJoined
    except:
        return "Could not get Hostname.", "Could not get Domain joined"


def DomainGrab(Host):
    global SMB1
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(0.7)
        s.connect(Host)
        h = SMBHeaderLanMan(cmd="\x72", mid="\x01\x00", flag1="\x00", flag2="\x00\x00")
        n = SMBNegoDataLanMan()
        packet0 = str(h) + str(n)
        buffer0 = longueur(packet0) + packet0
        s.send(NetworkSendBufferPython2or3(buffer0))
        data = s.recv(2048)
        s.close()
        if data[8:10] == b"\x72\x00":
            return GetHostnameAndDomainName(data)
    except IOError as e:
        if e.errno == errno.ECONNRESET:
            SMB1 = "Disabled"
            p("SMB1 is disabled on this host. Please choose another host.")
        else:
            return False


def SmbFinger(Host):
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.settimeout(Timeout)
        s.connect(Host)
    except:
        pass
    try:
        h = SMBHeader(cmd="\x72", flag1="\x18", flag2="\x53\xc8")
        n = SMBNego(Data=SMBNegoData())
        n.calculate()
        packet0 = str(h) + str(n)
        buffer0 = longueur(packet0) + packet0
        s.send(NetworkSendBufferPython2or3(buffer0))
        data = s.recv(2048)
        signing = IsSigningEnabled(data)
        if data[8:10] == b"\x72\x00":
            head = SMBHeader(cmd="\x73", flag1="\x18", flag2="\x17\xc8", uid="\x00\x00")
            t = SMBSessionFingerData()
            packet0 = str(head) + str(t)
            buffer1 = longueur(packet0) + packet0
            s.send(NetworkSendBufferPython2or3(buffer1))
            data = s.recv(2048)
        if data[8:10] == b"\x73\x16":
            OsVersion, ClientVersion = OsNameClientVersion(
                NetworkRecvBufferPython2or3(data)
            )
            return signing, OsVersion, ClientVersion
    except:
        pass


def SmbFingerSigning(Host):
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.settimeout(Timeout)
        s.connect((Host, 445))
    except:
        return False
    try:
        h = SMBHeader(cmd="\x72", flag1="\x18", flag2="\x53\xc8")
        n = SMBNego(Data=SMBNegoData())
        n.calculate()
        packet0 = str(h) + str(n)
        buffer0 = longueur(packet0) + packet0
        s.send(buffer0)
        data = s.recv(2048)
        signing = IsSigningEnabled(data)
        return signing
    except:
        pass


##################
# run it
def ShowResults(Host):
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.settimeout(Timeout)
        s.connect(Host)
    except:
        return False

    try:
        Hostname, DomainJoined = DomainGrab(Host)
        Signing, OsVer, LanManClient = SmbFinger(Host)
        enabled = color("SMB signing is mandatory. Choose another target", 1, 1)
        disabled = color("SMB signing: False", 2, 1)
        print(color("Retrieving information for %s..." % Host[0], 8, 1))
        print(enabled if Signing else disabled)
        print(color("Os version: '%s'" % (OsVer), 8, 3))
        print(
            color(
                "Hostname: '%s'\nPart of the '%s' domain" % (Hostname, DomainJoined),
                8,
                3,
            )
        )
    except:
        pass


def ShowSmallResults(Host):
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.settimeout(Timeout)
        s.connect(Host)
    except:
        return False

    try:
        Hostname, DomainJoined = DomainGrab(Host)
        Signing, OsVer, LanManClient = SmbFinger(Host)
        Message = color(
            "\n[+] Client info: ['%s', domain: '%s', signing:'%s']"
            % (OsVer, DomainJoined, Signing),
            4,
            0,
        )
        return Message
    except:
        return None


def ShowScanSmallResults(Host):
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.settimeout(Timeout)
        s.connect(Host)
    except:
        return False

    try:
        Hostname, DomainJoined = DomainGrab(Host)
        Signing, OsVer, LanManClient = SmbFinger(Host)
        Message = "['%s', Os:'%s', Domain:'%s', Signing:'%s']" % (
            Host[0],
            OsVer,
            DomainJoined,
            Signing,
        )
        print(Message)
    except:
        return None


def ShowSigning(Host):
    s = socket(AF_INET, SOCK_STREAM)
    try:
        s.settimeout(Timeout)
        s.connect((Host, 445))
    except:
        print("[Pivot Verification Failed]: Target host is down")
        return True

    try:
        Signing = SmbFingerSigning(Host)
        if Signing == True:
            print(
                "[Pivot Verification Failed]:Signing is enabled. Choose another host."
            )
            return True
        else:
            return False
    except:
        pass


def RunFinger(Host):
    m = re.search("/", str(Host))
    if m:
        net, _, mask = Host.partition("/")
        mask = int(mask)
        net = atod(net)
        for host in (dtoa(net + n) for n in range(0, 1 << 32 - mask)):
            ShowResults((host, 445))
    else:
        ShowResults((Host, 445))


def RunPivotScan(Host, CurrentIP):
    m = re.search("/", str(Host))
    if m:
        net, _, mask = Host.partition("/")
        mask = int(mask)
        net = atod(net)
        threads = []
        for host in (dtoa(net + n) for n in range(0, 1 << 32 - mask)):
            if CurrentIP == host:
                pass
            else:
                p = multiprocessing.Process(
                    target=ShowScanSmallResults, args=((host, 445),)
                )
                threads.append(p)
                p.start()
        sleep(1)
    else:
        ShowScanSmallResults((Host, 445))
