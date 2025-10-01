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

# Built-in imports
import os
import sys
import re
import logging
import socket
import datetime
import codecs
import struct
import random
from calendar import timegm

# External library imports
import netifaces
import aioquic

# Local library imports
from responder.src import settings


def if_nametoindex2(name):
    if settings.Config.PY2OR3 == "PY2":
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        ret = libc.if_nametoindex(name)
        return ret
    else:
        return socket.if_nametoindex(settings.Config.Interface)


def RandomChallenge():
    if settings.Config.PY2OR3 == "PY3":
        if settings.Config.NumChal == "random":
            from random import getrandbits

            NumChal = b"%016x" % getrandbits(16 * 4)
            Challenge = b""
            for i in range(0, len(NumChal), 2):
                Challenge += NumChal[i : i + 2]
            return codecs.decode(Challenge, "hex")
        else:
            return settings.Config.Challenge
    else:
        if settings.Config.NumChal == "random":
            from random import getrandbits

            NumChal = "%016x" % getrandbits(16 * 4)
            Challenge = ""
            for i in range(0, len(NumChal), 2):
                Challenge += NumChal[i : i + 2].decode("hex")
            return Challenge
        else:
            return settings.Config.Challenge


def HTTPCurrentDate():
    Date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    return Date


def SMBTime():
    dt = datetime.datetime.now()
    dt = dt.replace(tzinfo=None)
    if settings.Config.PY2OR3 == "PY3":
        return struct.pack(
            "<Q", 116444736000000000 + (timegm(dt.timetuple()) * 10000000)
        ).decode("latin-1")
    else:
        return struct.pack(
            "<Q", 116444736000000000 + (timegm(dt.timetuple()) * 10000000)
        )


try:
    import sqlite3
except:
    print("[!] Please install python-sqlite3 extension.")
    sys.exit(0)


def color(txt, code=1, modifier=0):
    if txt.startswith("[*]"):
        settings.Config.PoisonersLogger.warning(txt)
    elif "Analyze" in txt:
        settings.Config.AnalyzeLogger.warning(txt)

    if os.name == "nt":  # No colors for windows...
        return txt
    return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)


def text(txt):
    stripcolors = re.sub(
        r"\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?", "", txt
    )
    logging.info(stripcolors)
    if os.name == "nt":
        return txt
    return "\r" + re.sub(r"\[([^]]*)\]", "\033[1;34m[\\1]\033[0m", txt)


def IsOnTheSameSubnet(ip, net):
    net += "/24"
    ipaddr = int("".join(["%02x" % int(x) for x in ip.split(".")]), 16)
    netstr, bits = net.split("/")
    netaddr = int("".join(["%02x" % int(x) for x in netstr.split(".")]), 16)
    mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
    return (ipaddr & mask) == (netaddr & mask)


def RespondToThisIP(ClientIp):

    if ClientIp.startswith("127.0.0."):
        return False
    elif settings.Config.AutoIgnore and ClientIp in settings.Config.AutoIgnoreList:
        print(
            color("[*]", 3, 1),
            "Received request from auto-ignored client %s, not answering." % ClientIp,
        )
        return False
    elif settings.Config.RespondTo and ClientIp not in settings.Config.RespondTo:
        return False
    elif ClientIp in settings.Config.RespondTo or settings.Config.RespondTo == []:
        if ClientIp not in settings.Config.DontRespondTo:
            return True
    return False


def RespondToThisName(Name):

    if [i for i in settings.Config.DontRespondToTLD if Name.upper().endswith(i)]:
        return False
    elif (
        settings.Config.RespondToName
        and Name.upper() not in settings.Config.RespondToName
    ):
        return False
    elif (
        Name.upper() in settings.Config.RespondToName
        or settings.Config.RespondToName == []
    ):
        if Name.upper() not in settings.Config.DontRespondToName:
            return True
    return False


def RespondToThisHost(ClientIp, Name):
    return RespondToThisIP(ClientIp) and RespondToThisName(Name)


def RespondWithIPAton():
    if settings.Config.PY2OR3 == "PY2":
        if settings.Config.ExternalIP:
            return settings.Config.ExternalIPAton
        else:
            return settings.Config.IP_aton
    else:
        if settings.Config.ExternalIP:
            return settings.Config.ExternalIPAton.decode("latin-1")
        else:
            return settings.Config.IP_aton.decode("latin-1")


def RespondWithIPPton():
    if settings.Config.PY2OR3 == "PY2":
        if settings.Config.ExternalIP6:
            return settings.Config.ExternalIP6Pton
        else:
            return settings.Config.IP_Pton6
    else:
        if settings.Config.ExternalIP6:
            return settings.Config.ExternalIP6Pton.decode("latin-1")
        else:
            return settings.Config.IP_Pton6.decode("latin-1")


def RespondWithIP():
    if settings.Config.ExternalIP:
        return settings.Config.ExternalIP
    else:
        return settings.Config.Bind_To


def RespondWithIP6():
    if settings.Config.ExternalIP6:
        return settings.Config.ExternalIP6
    else:
        return settings.Config.Bind_To6


def OsInterfaceIsSupported():
    if settings.Config.Interface != "Not set":
        return not IsOsX()
    return False


def IsOsX():
    return sys.platform == "darwin"


def IsIPv6IP(IP):
    if IP == None:
        return False
    regex = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    ret = re.search(regex, IP)
    if ret:
        return True
    else:
        return False


def FindLocalIP(Iface, OURIP):
    if Iface == "ALL":
        return "0.0.0.0"

    try:
        if IsOsX():
            return OURIP

        elif IsIPv6IP(OURIP):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, 25, str(Iface + "\0").encode("utf-8"))
            s.connect(("127.0.0.1", 9))  # RFC 863
            ret = s.getsockname()[0]
            s.close()
            return ret

        elif IsIPv6IP(OURIP) == False and OURIP != None:
            return OURIP

        elif OURIP == None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, 25, str(Iface + "\0").encode("utf-8"))
            s.connect(("127.0.0.1", 9))  # RFC 863
            ret = s.getsockname()[0]
            s.close()
            return ret

    except socket.error:
        print(color("[!] Error: %s: Interface not found" % Iface, 1))
        sys.exit(-1)


def Probe_IPv6_socket():
    """Return true is IPv6 sockets are really supported, and False when IPv6 is not supported."""
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except:
        return False


def FindLocalIP6(Iface, OURIP):
    if Iface == "ALL":
        return "::"

    try:

        if IsIPv6IP(OURIP) == False:

            try:
                # Let's make it random so we don't get spotted easily.
                randIP = "2001:" + ":".join(
                    ("%x" % random.randint(0, 16**4) for i in range(7))
                )
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                s.connect((randIP + ":80", 1))
                IP = s.getsockname()[0]
                return IP
            except:
                try:
                    # Try harder; Let's get the local link addr
                    IP = str(
                        netifaces.ifaddresses(Iface)[netifaces.AF_INET6][0][
                            "addr"
                        ].replace("%" + Iface, "")
                    )
                    return IP
                except:
                    IP = "::1"
                    print("[+] You don't have an IPv6 address assigned.")
                    return IP

        else:
            return OURIP

    except socket.error:
        print(color("[!] Error: %s: Interface not found" % Iface, 1))
        sys.exit(-1)


# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):
    logging.info("[*] Captured Hash: %s" % data)
    if not os.path.isfile(outfile):
        with open(outfile, "w") as outf:
            outf.write(data + "\n")
        return
    with open(outfile, "r") as filestr:
        if re.search(user.encode("hex"), filestr.read().encode("hex")):
            return False
        elif re.search(re.escape("$"), user):
            return False
    with open(outfile, "a") as outf2:
        outf2.write(data + "\n")


# Function used to write debug config and network info.
def DumpConfig(outfile, data):
    with open(outfile, "a") as dump:
        dump.write(data + "\n")


def StructPython2or3(endian, data):
    # Python2...
    if settings.Config.PY2OR3 == "PY2":
        return struct.pack(endian, len(data))
    # Python3...
    else:
        return struct.pack(endian, len(data)).decode("latin-1")


def StructWithLenPython2or3(endian, data):
    # Python2...
    if settings.Config.PY2OR3 == "PY2":
        return struct.pack(endian, data)
    # Python3...
    else:
        return struct.pack(endian, data).decode("latin-1")


def NetworkSendBufferPython2or3(data):
    if settings.Config.PY2OR3 == "PY2":
        return str(data)
    else:
        return bytes(str(data), "latin-1")


def NetworkRecvBufferPython2or3(data):
    if settings.Config.PY2OR3 == "PY2":
        return str(data)
    else:
        return str(data.decode("latin-1"))


def CreateResponderDb():
    if not os.path.exists(str(settings.LOGS_PATH / "Responder.db")):
        cursor = sqlite3.connect(str(settings.LOGS_PATH / "Responder.db"))
        cursor.execute(
            "CREATE TABLE Poisoned (timestamp TEXT, Poisoner TEXT, SentToIp TEXT, ForName TEXT, AnalyzeMode TEXT)"
        )
        cursor.commit()
        cursor.execute(
            "CREATE TABLE responder (timestamp TEXT, module TEXT, type TEXT, client TEXT, hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
        )
        cursor.commit()
        cursor.execute(
            "CREATE TABLE DHCP (timestamp TEXT, MAC TEXT, IP TEXT, RequestedIP TEXT)"
        )
        cursor.commit()
        cursor.close()


def SaveToDb(result):

    for k in [
        "module",
        "type",
        "client",
        "hostname",
        "user",
        "cleartext",
        "hash",
        "fullhash",
    ]:
        if not k in result:
            result[k] = ""
    result["client"] = result["client"].replace("::ffff:", "")
    if len(result["user"]) < 2:
        print(color("[*] Skipping one character username: %s" % result["user"], 3, 1))
        text("[*] Skipping one character username: %s" % result["user"])
        return

    cursor = sqlite3.connect(str(settings.LOGS_PATH / "Responder.db"))
    cursor.text_factory = (
        sqlite3.Binary
    )  # We add a text factory to support different charsets

    if len(result["cleartext"]):
        fname = "%s-%s-ClearText-%s.txt" % (
            result["module"],
            result["type"],
            result["client"],
        )
        res = cursor.execute(
            "SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND client=? AND LOWER(user)=LOWER(?) AND cleartext=?",
            (
                result["module"],
                result["type"],
                result["client"],
                result["user"],
                result["cleartext"],
            ),
        )
    else:
        fname = "%s-%s-%s.txt" % (result["module"], result["type"], result["client"])
        res = cursor.execute(
            "SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND client=? AND LOWER(user)=LOWER(?)",
            (result["module"], result["type"], result["client"], result["user"]),
        )

    (count,) = res.fetchone()
    logfile = settings.LOGS_PATH / fname

    if not count:
        cursor.execute(
            "INSERT INTO responder VALUES(datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result["module"],
                result["type"],
                result["client"],
                result["hostname"],
                result["user"],
                result["cleartext"],
                result["hash"],
                result["fullhash"],
            ),
        )
        cursor.commit()

    if not count or settings.Config.CaptureMultipleHashFromSameHost:
        with open(logfile, "a") as outf:
            if len(
                result["cleartext"]
            ):  # If we obtained cleartext credentials, write them to file
                outf.write(
                    "%s:%s\n"
                    % (
                        result["user"].encode("utf8", "replace"),
                        result["cleartext"].encode("utf8", "replace"),
                    )
                )
            else:  # Otherwise, write JtR-style hash string to file
                outf.write(
                    result["fullhash"] + "\n"
                )  # .encode('utf8', 'replace') + '\n')

    if not count or settings.Config.Verbose:  # Print output
        if len(result["client"]):
            print(
                text(
                    "[%s] %s Client   : %s"
                    % (result["module"], result["type"], color(result["client"], 3))
                )
            )

        if len(result["hostname"]):
            print(
                text(
                    "[%s] %s Hostname : %s"
                    % (result["module"], result["type"], color(result["hostname"], 3))
                )
            )

        if len(result["user"]):
            print(
                text(
                    "[%s] %s Username : %s"
                    % (result["module"], result["type"], color(result["user"], 3))
                )
            )

        # Bu order of priority, print cleartext, fullhash, or hash
        if len(result["cleartext"]):
            print(
                text(
                    "[%s] %s Password : %s"
                    % (result["module"], result["type"], color(result["cleartext"], 3))
                )
            )

        elif len(result["fullhash"]):
            print(
                text(
                    "[%s] %s Hash     : %s"
                    % (result["module"], result["type"], color(result["fullhash"], 3))
                )
            )

        elif len(result["hash"]):
            print(
                text(
                    "[%s] %s Hash     : %s"
                    % (result["module"], result["type"], color(result["hash"], 3))
                )
            )

        # Appending auto-ignore list if required
        # Except if this is a machine account's hash
        if settings.Config.AutoIgnore and not result["user"].endswith("$"):
            settings.Config.AutoIgnoreList.append(result["client"])
            print(
                color(
                    "[*] Adding client %s to auto-ignore list" % result["client"], 4, 1
                )
            )
    elif len(result["cleartext"]):
        print(
            color(
                "[*] Skipping previously captured cleartext password for %s"
                % result["user"],
                3,
                1,
            )
        )
        text(
            "[*] Skipping previously captured cleartext password for %s"
            % result["user"]
        )
    else:
        print(
            color("[*] Skipping previously captured hash for %s" % result["user"], 3, 1)
        )
        text("[*] Skipping previously captured hash for %s" % result["user"])
        cursor.execute(
            "UPDATE responder SET timestamp=datetime('now') WHERE user=? AND client=?",
            (result["user"], result["client"]),
        )
        cursor.commit()
    cursor.close()


def SavePoisonersToDb(result):

    for k in ["Poisoner", "SentToIp", "ForName", "AnalyzeMode"]:
        if not k in result:
            result[k] = ""
    result["SentToIp"] = result["SentToIp"].replace("::ffff:", "")
    cursor = sqlite3.connect(str(settings.LOGS_PATH / "Responder.db"))
    cursor.text_factory = (
        sqlite3.Binary
    )  # We add a text factory to support different charsets
    res = cursor.execute(
        "SELECT COUNT(*) AS count FROM Poisoned WHERE Poisoner=? AND SentToIp=? AND ForName=? AND AnalyzeMode=?",
        (
            result["Poisoner"],
            result["SentToIp"],
            result["ForName"],
            result["AnalyzeMode"],
        ),
    )
    (count,) = res.fetchone()

    if not count:
        cursor.execute(
            "INSERT INTO Poisoned VALUES(datetime('now'), ?, ?, ?, ?)",
            (
                result["Poisoner"],
                result["SentToIp"],
                result["ForName"],
                result["AnalyzeMode"],
            ),
        )
        cursor.commit()

    cursor.close()


def SaveDHCPToDb(result):
    for k in ["MAC", "IP", "RequestedIP"]:
        if not k in result:
            result[k] = ""

    cursor = sqlite3.connect(str(settings.LOGS_PATH / "Responder.db"))
    cursor.text_factory = (
        sqlite3.Binary
    )  # We add a text factory to support different charsets
    res = cursor.execute(
        "SELECT COUNT(*) AS count FROM DHCP WHERE MAC=? AND IP=? AND RequestedIP=?",
        (result["MAC"], result["IP"], result["RequestedIP"]),
    )
    (count,) = res.fetchone()

    if not count:
        cursor.execute(
            "INSERT INTO DHCP VALUES(datetime('now'), ?, ?, ?)",
            (result["MAC"], result["IP"], result["RequestedIP"]),
        )
        cursor.commit()

    cursor.close()


def Parse_IPV6_Addr(data):
    if data[len(data) - 4 : len(data)] == b"\x00\x1c\x00\x01":
        return "IPv6"
    elif data[len(data) - 4 : len(data)] == b"\x00\x01\x00\x01":
        return True
    elif data[len(data) - 4 : len(data)] == b"\x00\xff\x00\x01":
        return True
    return False


def IsIPv6(data):
    if "::ffff:" in data:
        return False
    else:
        return True


def Decode_Name(
    nbname,
):  # From http://code.google.com/p/dpkt/ with author's permission.
    try:
        from string import printable

        if len(nbname) != 32:
            return nbname

        l = []
        for i in range(0, 32, 2):
            l.append(
                chr(
                    ((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i + 1]) - 0x41) & 0xF)
                )
            )

        return "".join(
            list(
                filter(
                    lambda x: x in printable,
                    "".join(l).split("\x00", 1)[0].replace(" ", ""),
                )
            )
        )
    except:
        return "Illegal NetBIOS name"


def NBT_NS_Role(data):
    return {
        "\x41\x41\x00": "Workstation/Redirector",
        "\x42\x4c\x00": "Domain Master Browser",
        "\x42\x4d\x00": "Domain Controller",
        "\x42\x4e\x00": "Local Master Browser",
        "\x42\x4f\x00": "Browser Election",
        "\x43\x41\x00": "File Server",
        "\x41\x42\x00": "Browser",
    }.get(data, "Service not known")


def banner():
    banner = "\n".join(
        [
            "                                         __",
            "  .----.-----.-----.-----.-----.-----.--|  |.-----.----.",
            "  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|",
            "  |__| |_____|_____|   __|_____|__|__|_____||_____|__|",
            "                   |__|",
        ]
    )

    print(banner)
    print("")


def StartupMessage():
    enabled = color("[ON]", 2, 1)
    disabled = color("[OFF]", 1, 1)
    print("")
    print(color("[+] ", 2, 1) + "Poisoners:")
    print(
        "    %-27s" % "LLMNR"
        + (
            enabled
            if (settings.Config.AnalyzeMode == False and settings.Config.LLMNR_On_Off)
            else disabled
        )
    )
    print(
        "    %-27s" % "NBT-NS"
        + (
            enabled
            if (settings.Config.AnalyzeMode == False and settings.Config.NBTNS_On_Off)
            else disabled
        )
    )
    print(
        "    %-27s" % "MDNS"
        + (
            enabled
            if (settings.Config.AnalyzeMode == False and settings.Config.MDNS_On_Off)
            else disabled
        )
    )
    print("    %-27s" % "DNS" + enabled)
    print("    %-27s" % "DHCP" + (enabled if settings.Config.DHCP_On_Off else disabled))
    print("")

    print(color("[+] ", 2, 1) + "Servers:")
    print(
        "    %-27s" % "HTTP server"
        + (enabled if settings.Config.HTTP_On_Off else disabled)
    )
    print(
        "    %-27s" % "HTTPS server"
        + (enabled if settings.Config.SSL_On_Off else disabled)
    )
    print(
        "    %-27s" % "WPAD proxy"
        + (enabled if settings.Config.WPAD_On_Off else disabled)
    )
    print(
        "    %-27s" % "Auth proxy"
        + (enabled if settings.Config.ProxyAuth_On_Off else disabled)
    )
    print(
        "    %-27s" % "SMB server"
        + (enabled if settings.Config.SMB_On_Off else disabled)
    )
    print(
        "    %-27s" % "Kerberos server"
        + (enabled if settings.Config.Krb_On_Off else disabled)
    )
    print(
        "    %-27s" % "SQL server"
        + (enabled if settings.Config.SQL_On_Off else disabled)
    )
    print(
        "    %-27s" % "FTP server"
        + (enabled if settings.Config.FTP_On_Off else disabled)
    )
    print(
        "    %-27s" % "IMAP server"
        + (enabled if settings.Config.IMAP_On_Off else disabled)
    )
    print(
        "    %-27s" % "POP3 server"
        + (enabled if settings.Config.POP_On_Off else disabled)
    )
    print(
        "    %-27s" % "SMTP server"
        + (enabled if settings.Config.SMTP_On_Off else disabled)
    )
    print(
        "    %-27s" % "DNS server"
        + (enabled if settings.Config.DNS_On_Off else disabled)
    )
    print(
        "    %-27s" % "LDAP server"
        + (enabled if settings.Config.LDAP_On_Off else disabled)
    )
    print(
        "    %-27s" % "MQTT server"
        + (enabled if settings.Config.MQTT_On_Off else disabled)
    )
    print(
        "    %-27s" % "RDP server"
        + (enabled if settings.Config.RDP_On_Off else disabled)
    )
    print(
        "    %-27s" % "DCE-RPC server"
        + (enabled if settings.Config.DCERPC_On_Off else disabled)
    )
    print(
        "    %-27s" % "WinRM server"
        + (enabled if settings.Config.WinRM_On_Off else disabled)
    )
    print(
        "    %-27s" % "SNMP server"
        + (enabled if settings.Config.SNMP_On_Off else disabled)
    )
    print("")

    print(color("[+] ", 2, 1) + "HTTP Options:")
    print(
        "    %-27s" % "Always serving EXE"
        + (enabled if settings.Config.Serve_Always else disabled)
    )
    print(
        "    %-27s" % "Serving EXE"
        + (enabled if settings.Config.Serve_Exe else disabled)
    )
    print(
        "    %-27s" % "Serving HTML"
        + (enabled if settings.Config.Serve_Html else disabled)
    )
    print(
        "    %-27s" % "Upstream Proxy"
        + (enabled if settings.Config.Upstream_Proxy else disabled)
    )
    # print('    %-27s' % "WPAD script" + settings.Config.WPAD_Script
    print("")

    print(color("[+] ", 2, 1) + "Poisoning Options:")
    print(
        "    %-27s" % "Analyze Mode"
        + (enabled if settings.Config.AnalyzeMode else disabled)
    )
    print(
        "    %-27s" % "Force WPAD auth"
        + (enabled if settings.Config.Force_WPAD_Auth else disabled)
    )
    print(
        "    %-27s" % "Force Basic Auth"
        + (enabled if settings.Config.Basic else disabled)
    )
    print(
        "    %-27s" % "Force LM downgrade"
        + (enabled if settings.Config.LM_On_Off == True else disabled)
    )
    print(
        "    %-27s" % "Force ESS downgrade"
        + (
            enabled
            if settings.Config.NOESS_On_Off == True or settings.Config.LM_On_Off == True
            else disabled
        )
    )
    print("")

    print(color("[+] ", 2, 1) + "Generic Options:")
    print(
        "    %-27s" % "Responder NIC" + color("[%s]" % settings.Config.Interface, 5, 1)
    )
    print("    %-27s" % "Responder IP" + color("[%s]" % settings.Config.Bind_To, 5, 1))
    print(
        "    %-27s" % "Responder IPv6" + color("[%s]" % settings.Config.Bind_To6, 5, 1)
    )
    if settings.Config.ExternalIP:
        print(
            "    %-27s" % "Responder external IP"
            + color("[%s]" % settings.Config.ExternalIP, 5, 1)
        )
    if settings.Config.ExternalIP6:
        print(
            "    %-27s" % "Responder external IPv6"
            + color("[%s]" % settings.Config.ExternalIP6, 5, 1)
        )

    print("    %-27s" % "Challenge set" + color("[%s]" % settings.Config.NumChal, 5, 1))
    if settings.Config.Upstream_Proxy:
        print(
            "    %-27s" % "Upstream Proxy"
            + color("[%s]" % settings.Config.Upstream_Proxy, 5, 1)
        )

    if len(settings.Config.RespondTo):
        print("    %-27s" % "Respond To" + color(str(settings.Config.RespondTo), 5, 1))
    if len(settings.Config.RespondToName):
        print(
            "    %-27s" % "Respond To Names"
            + color(str(settings.Config.RespondToName), 5, 1)
        )
    if len(settings.Config.DontRespondTo):
        print(
            "    %-27s" % "Don't Respond To"
            + color(str(settings.Config.DontRespondTo), 5, 1)
        )
    if len(settings.Config.DontRespondToName):
        print(
            "    %-27s" % "Don't Respond To Names"
            + color(str(settings.Config.DontRespondToName), 5, 1)
        )
    if len(settings.Config.DontRespondToTLD):
        print(
            "    %-27s" % "Don't Respond To MDNS TLD"
            + color(str(settings.Config.DontRespondToTLD), 5, 1)
        )
    if settings.Config.TTL == None:
        print("    %-27s" % "TTL for poisoned response " + color("[default]", 5, 1))
    else:
        print(
            "    %-27s" % "TTL for poisoned response"
            + color(
                str(settings.Config.TTL.encode().hex())
                + " ("
                + str(int.from_bytes(str.encode(settings.Config.TTL), "big"))
                + " seconds)",
                5,
                1,
            )
        )
    print("")

    print(color("[+] ", 2, 1) + "Current Session Variables:")
    print(
        "    %-27s" % "Responder Machine Name"
        + color("[%s]" % settings.Config.MachineName, 5, 1)
    )
    print(
        "    %-27s" % "Responder Domain Name"
        + color("[%s]" % settings.Config.DomainName, 5, 1)
    )
    print(
        "    %-27s" % "Responder DCE-RPC Port "
        + color("[%s]" % settings.Config.RPCPort, 5, 1)
    )

    # credits
    print("")
    print(color("[*] ", 2, 1) + "Version: " + settings.__version__)
    print(color("[*] ", 2, 1) + "Author: Laurent Gaffie, <lgaffie@secorizon.com>")
    print(
        color("[*] ", 2, 1) + "To sponsor Responder: https://paypal.me/PythonResponder"
    )
