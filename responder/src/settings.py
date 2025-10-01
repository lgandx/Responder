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
import random
import subprocess
import logging
import socket
import configparser as ConfigParser
import re

# Local library imports
from pathlib import Path

__version__ = "Responder 3.1.7.0"

# Centralized logging configuration
LOGS_PATH = Path.cwd() / "responder-logs"
LOGS_PATH.mkdir(exist_ok=True)  # Create directory if it doesn't exist


def get_config() -> ConfigParser.ConfigParser:
    # Config parsing - Look for user config first, then fall back to default
    user_config_path = Path.cwd() / "responder.conf"
    default_config_path = os.path.join(os.path.dirname(__file__), "Responder.conf")

    config = ConfigParser.ConfigParser()

    # Track which config was actually loaded
    config_loaded = False
    is_user_config = False

    if user_config_path.exists():
        try:
            config.read(user_config_path)
            config_loaded = True
            is_user_config = True
        except Exception:
            pass

    if not config_loaded:
        try:
            config.read(default_config_path)
            config_loaded = True
            is_user_config = False
        except Exception:
            pass

    # Store metadata about which config was loaded
    config._is_user_config = is_user_config
    config._config_base_path = Path.cwd() if is_user_config else Path(os.path.dirname(__file__))

    # If no config could be loaded, create minimal default sections
    if not config_loaded or not config.has_section('Responder Core'):
        config.add_section('Responder Core')
        config.set('Responder Core', 'RespondTo', '')
        config.set('Responder Core', 'DontRespondTo', '')
        config.set('Responder Core', 'LLMNR', 'On')
        config.set('Responder Core', 'NBTNS', 'On')
        config.set('Responder Core', 'MDNS', 'On')
        config.set('Responder Core', 'HTTP', 'On')
        config.set('Responder Core', 'HTTPS', 'On')
        config.set('Responder Core', 'SMB', 'On')
        config.set('Responder Core', 'SQL', 'On')
        config.set('Responder Core', 'FTP', 'On')
        config.set('Responder Core', 'POP', 'On')
        config.set('Responder Core', 'IMAP', 'On')
        config.set('Responder Core', 'SMTP', 'On')
        config.set('Responder Core', 'LDAP', 'On')
        config.set('Responder Core', 'DNS', 'On')
        config.set('Responder Core', 'RDP', 'On')
        config.set('Responder Core', 'DCERPC', 'On')
        config.set('Responder Core', 'WINRM', 'On')
        config.set('Responder Core', 'Kerberos', 'On')
        config.set('Responder Core', 'SNMP', 'On')
        config.set('Responder Core', 'MQTT', 'On')
        config.set('Responder Core', 'QUIC', 'On')
        config.set('Responder Core', 'SessionLog', 'Responder-Session.log')
        config.set('Responder Core', 'PoisonersLog', 'Poisoners-Session.log')
        config.set('Responder Core', 'AnalyzeLog', 'Analyze-Session.log')
        config.set('Responder Core', 'ResponderConfigDump', 'Config-Responder.log')
        config.set('Responder Core', 'AutoIgnoreAfterSuccess', 'Off')
        config.set('Responder Core', 'CaptureMultipleCredentials', 'On')
        config.set('Responder Core', 'CaptureMultipleHashFromSameHost', 'Off')
        config.set('Responder Core', 'Challenge', '1122334455667788')
        config.set('Responder Core', 'RespondToName', '')
        config.set('Responder Core', 'DontRespondToTLD', '')
        config.set('Responder Core', 'DontRespondToName', '')

    if not config.has_section('HTTP Server'):
        config.add_section('HTTP Server')
        config.set('HTTP Server', 'Serve-Exe', 'Off')
        config.set('HTTP Server', 'Serve-Always', 'Off')
        config.set('HTTP Server', 'Serve-Html', 'Off')
        config.set('HTTP Server', 'HtmlFilename', 'files/AccessDenied.html')
        config.set('HTTP Server', 'ExeFilename', 'files/BindShell.exe')
        config.set('HTTP Server', 'ExeDownloadName', 'ProxyClient.exe')
        config.set('HTTP Server', 'WPADScript', '')
        config.set('HTTP Server', 'HTMLToInject', '')

    if not config.has_section('HTTPS Server'):
        config.add_section('HTTPS Server')
        config.set('HTTPS Server', 'SSLKey', 'certs/responder.key')
        config.set('HTTPS Server', 'SSLCert', 'certs/responder.crt')

    return config


class Settings:

    def __init__(self):
        self.Bind_To = "0.0.0.0"
        self._config = None
        self._config_loaded = False

        # Initialize all attributes that might be accessed during import
        # These will be properly set later in populate()
        self.NOESS_On_Off = False
        self.PY2OR3 = "PY3" if sys.version_info > (3, 0) else "PY2"

        # Initialize empty attributes for import-time access
        self.RespondTo = []
        self.DontRespondTo = []
        self.Interface = None

    @property
    def config(self):
        """Lazy loading of configuration - only loads when first accessed"""
        if not self._config_loaded:
            self._config = get_config()
            self._config_loaded = True
        return self._config

    def __str__(self):
        ret = "Settings class:\n"
        for attr in dir(self):
            value = str(getattr(self, attr)).strip()
            ret += "    Settings.%s = %s\n" % (attr, value)
        return ret

    def toBool(self, str):
        return str.upper() == "ON"

    def ExpandIPRanges(self):
        def expand_ranges(lst):
            ret = []
            for l in lst:
                if (
                    ":" in l
                ):  # For IPv6 addresses, similar to the IPv4 version below but hex and pads :'s to expand shortend addresses
                    while l.count(":") < 7:
                        pos = l.find("::")
                        l = l[:pos] + ":" + l[pos:]
                    tab = l.split(":")
                    x = {}
                    i = 0
                    xaddr = ""
                    for byte in tab:
                        if byte == "":
                            byte = "0"
                        if "-" not in byte:
                            x[i] = x[i + 1] = int(byte, base=16)
                        else:
                            b = byte.split("-")
                            x[i] = int(b[0], base=16)
                            x[i + 1] = int(b[1], base=16)
                        i += 2
                    for a in range(x[0], x[1] + 1):
                        for b in range(x[2], x[3] + 1):
                            for c in range(x[4], x[5] + 1):
                                for d in range(x[6], x[7] + 1):
                                    for e in range(x[8], x[9] + 1):
                                        for f in range(x[10], x[11] + 1):
                                            for g in range(x[12], x[13] + 1):
                                                for h in range(x[14], x[15] + 1):
                                                    xaddr = (
                                                        "%x:%x:%x:%x:%x:%x:%x:%x"
                                                        % (a, b, c, d, e, f, g, h)
                                                    )
                                                    xaddr = re.sub(
                                                        "(^|:)0{1,4}",
                                                        ":",
                                                        xaddr,
                                                        count=7,
                                                    )  # Compresses expanded IPv6 address
                                                    xaddr = re.sub(
                                                        ":{3,7}", "::", xaddr, count=7
                                                    )
                                                    ret.append(xaddr)
                else:
                    tab = l.split(".")
                    x = {}
                    i = 0
                    for byte in tab:
                        if "-" not in byte:
                            x[i] = x[i + 1] = int(byte)
                        else:
                            b = byte.split("-")
                            x[i] = int(b[0])
                            x[i + 1] = int(b[1])
                        i += 2
                    for a in range(x[0], x[1] + 1):
                        for b in range(x[2], x[3] + 1):
                            for c in range(x[4], x[5] + 1):
                                for d in range(x[6], x[7] + 1):
                                    ret.append("%d.%d.%d.%d" % (a, b, c, d))
            return ret

        self.RespondTo = expand_ranges(self.RespondTo)
        self.DontRespondTo = expand_ranges(self.DontRespondTo)

    def populate(self, options):
        # Import utils here to avoid circular import
        from responder.src import utils

        if options.Interface == None and utils.IsOsX() == False:
            print(utils.color("Error: -I <if> mandatory option is missing", 1))
            sys.exit(-1)

        if options.Interface == "ALL" and options.OURIP == None:
            print(
                utils.color(
                    "Error: -i is missing.\nWhen using -I ALL you need to provide your current ip address",
                    1,
                )
            )
            sys.exit(-1)
        # Python version
        if sys.version_info > (3, 0):
            self.PY2OR3 = "PY3"
        else:
            self.PY2OR3 = "PY2"

        # Poisoners
        self.LLMNR_On_Off = self.toBool(self.config.get("Responder Core", "LLMNR"))
        self.NBTNS_On_Off = self.toBool(self.config.get("Responder Core", "NBTNS"))
        self.MDNS_On_Off = self.toBool(self.config.get("Responder Core", "MDNS"))

        # Servers
        self.HTTP_On_Off = self.toBool(self.config.get("Responder Core", "HTTP"))
        self.SSL_On_Off = self.toBool(self.config.get("Responder Core", "HTTPS"))
        self.SMB_On_Off = self.toBool(self.config.get("Responder Core", "SMB"))
        self.QUIC_On_Off = self.toBool(self.config.get("Responder Core", "QUIC"))
        self.SQL_On_Off = self.toBool(self.config.get("Responder Core", "SQL"))
        self.FTP_On_Off = self.toBool(self.config.get("Responder Core", "FTP"))
        self.POP_On_Off = self.toBool(self.config.get("Responder Core", "POP"))
        self.IMAP_On_Off = self.toBool(self.config.get("Responder Core", "IMAP"))
        self.SMTP_On_Off = self.toBool(self.config.get("Responder Core", "SMTP"))
        self.LDAP_On_Off = self.toBool(self.config.get("Responder Core", "LDAP"))
        self.MQTT_On_Off = self.toBool(self.config.get("Responder Core", "MQTT"))
        self.DNS_On_Off = self.toBool(self.config.get("Responder Core", "DNS"))
        self.RDP_On_Off = self.toBool(self.config.get("Responder Core", "RDP"))
        self.DCERPC_On_Off = self.toBool(self.config.get("Responder Core", "DCERPC"))
        self.WinRM_On_Off = self.toBool(self.config.get("Responder Core", "WINRM"))
        self.Krb_On_Off = self.toBool(self.config.get("Responder Core", "Kerberos"))
        self.SNMP_On_Off = self.toBool(self.config.get("Responder Core", "SNMP"))


        self.DatabaseFile = LOGS_PATH / "Responder.db"

        # Ensure the database directory exists and create database if needed
        LOGS_PATH.mkdir(exist_ok=True)
        if not self.DatabaseFile.exists():
            import sqlite3
            try:
                cursor = sqlite3.connect(str(self.DatabaseFile))
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS Poisoned (timestamp TEXT, Poisoner TEXT, SentToIp TEXT, ForName TEXT, AnalyzeMode TEXT)"
                )
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS responder (timestamp TEXT, module TEXT, type TEXT, client TEXT, hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
                )
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS DHCP (timestamp TEXT, MAC TEXT, IP TEXT, RequestedIP TEXT)"
                )
                cursor.commit()
                cursor.close()
            except Exception as e:
                print(utils.color(f"[!] Warning: Could not create database: {e}", 3, 1))

        # Log Files - Use centralized logging directory
        self.LogDir = LOGS_PATH

        self.SessionLogFile = self.LogDir / self.config.get(
            "Responder Core", "SessionLog"
        )
        self.PoisonersLogFile = self.LogDir / self.config.get(
            "Responder Core", "PoisonersLog"
        )
        self.AnalyzeLogFile = self.LogDir / self.config.get(
            "Responder Core", "AnalyzeLog"
        )
        self.ResponderConfigDump = self.LogDir / self.config.get(
            "Responder Core", "ResponderConfigDump"
        )

        # CLI options
        self.ExternalIP = options.ExternalIP
        self.LM_On_Off = options.LM_On_Off
        self.NOESS_On_Off = options.NOESS_On_Off
        self.WPAD_On_Off = options.WPAD_On_Off
        self.DHCP_On_Off = options.DHCP_On_Off
        self.Basic = options.Basic
        self.Interface = options.Interface
        self.OURIP = options.OURIP
        self.Force_WPAD_Auth = options.Force_WPAD_Auth
        self.Upstream_Proxy = options.Upstream_Proxy
        self.AnalyzeMode = options.Analyze
        self.Verbose = options.Verbose
        self.ProxyAuth_On_Off = options.ProxyAuth_On_Off
        self.CommandLine = str(sys.argv)
        self.Bind_To = utils.FindLocalIP(self.Interface, self.OURIP)
        self.Bind_To6 = utils.FindLocalIP6(self.Interface, self.OURIP)
        self.DHCP_DNS = options.DHCP_DNS
        self.ExternalIP6 = options.ExternalIP6
        self.Quiet_Mode = options.Quiet
        self.AnswerName = options.AnswerName
        self.ErrorCode = options.ErrorCode

        # TTL blacklist. Known to be detected by SOC / XDR
        TTL_blacklist = [b"\x00\x00\x00\x1e", b"\x00\x00\x00\x78", b"\x00\x00\x00\xa5"]
        # Lets add a default mode, which uses Windows default TTL for each protocols (set respectively in packets.py)
        if options.TTL is None:
            self.TTL = None

        # Random TTL
        elif options.TTL.upper() == "RANDOM":
            TTL = bytes.fromhex("000000" + format(random.randint(10, 90), "x"))
            if TTL in TTL_blacklist:
                TTL = int.from_bytes(TTL, "big") + 1
                TTL = int.to_bytes(TTL, 4)
            self.TTL = TTL.decode("utf-8")
        else:
            self.TTL = bytes.fromhex("000000" + options.TTL).decode("utf-8")

        # Do we have IPv6 for real?
        self.IPv6 = utils.Probe_IPv6_socket()

        if self.Interface == "ALL":
            self.Bind_To_ALL = True
        else:
            self.Bind_To_ALL = False
        # IPV4
        if self.Interface == "ALL":
            self.IP_aton = socket.inet_aton(self.OURIP)
        else:
            self.IP_aton = socket.inet_aton(self.Bind_To)
        # IPV6
        if self.Interface == "ALL":
            if self.OURIP != None and utils.IsIPv6IP(self.OURIP):
                self.IP_Pton6 = socket.inet_pton(socket.AF_INET6, self.OURIP)
        else:
            self.IP_Pton6 = socket.inet_pton(socket.AF_INET6, self.Bind_To6)

        # External IP
        if self.ExternalIP:
            if utils.IsIPv6IP(self.ExternalIP):
                sys.exit(
                    utils.color(
                        "[!] IPv6 address provided with -e parameter. Use -6 IPv6_address instead.",
                        1,
                    )
                )

            self.ExternalIPAton = socket.inet_aton(self.ExternalIP)
            self.ExternalResponderIP = utils.RespondWithIP()
        else:
            self.ExternalResponderIP = self.Bind_To

        # External IPv6
        if self.ExternalIP6:
            self.ExternalIP6Pton = socket.inet_pton(socket.AF_INET6, self.ExternalIP6)
            self.ExternalResponderIP6 = utils.RespondWithIP6()
        else:
            self.ExternalResponderIP6 = self.Bind_To6

        self.Os_version = sys.platform

        self.FTPLog = LOGS_PATH / "FTP-Clear-Text-Password-{}.txt"
        self.IMAPLog = LOGS_PATH / "IMAP-Clear-Text-Password-{}.txt"
        self.POP3Log = LOGS_PATH / "POP3-Clear-Text-Password-{}.txt"
        self.HTTPBasicLog = LOGS_PATH / "HTTP-Clear-Text-Password-{}.txt"
        self.LDAPClearLog = LOGS_PATH / "LDAP-Clear-Text-Password-{}.txt"
        self.MQTTLog = LOGS_PATH / "MQTT-Clear-Text-Password-{}.txt"
        self.SMBClearLog = LOGS_PATH / "SMB-Clear-Text-Password-{}.txt"
        self.SMTPClearLog = LOGS_PATH / "SMTP-Clear-Text-Password-{}.txt"
        self.MSSQLClearLog = LOGS_PATH / "MSSQL-Clear-Text-Password-{}.txt"
        self.SNMPLog = LOGS_PATH / "SNMP-Clear-Text-Password-{}.txt"

        self.LDAPNTLMv1Log = LOGS_PATH / "LDAP-NTLMv1-Client-{}.txt"
        self.HTTPNTLMv1Log = LOGS_PATH / "HTTP-NTLMv1-Client-{}.txt"
        self.HTTPNTLMv2Log = LOGS_PATH / "HTTP-NTLMv2-Client-{}.txt"
        self.KerberosLog = LOGS_PATH / "MSKerberos-Client-{}.txt"
        self.MSSQLNTLMv1Log = LOGS_PATH / "MSSQL-NTLMv1-Client-{}.txt"
        self.MSSQLNTLMv2Log = LOGS_PATH / "MSSQL-NTLMv2-Client-{}.txt"
        self.SMBNTLMv1Log = LOGS_PATH / "SMB-NTLMv1-Client-{}.txt"
        self.SMBNTLMv2Log = LOGS_PATH / "SMB-NTLMv2-Client-{}.txt"
        self.SMBNTLMSSPv1Log = LOGS_PATH / "SMB-NTLMSSPv1-Client-{}.txt"
        self.SMBNTLMSSPv2Log = LOGS_PATH / "SMB-NTLMSSPv2-Client-{}.txt"

        # HTTP Options - resolve paths based on config source
        self.Serve_Exe        = self.toBool(self.config.get('HTTP Server', 'Serve-Exe'))
        self.Serve_Always     = self.toBool(self.config.get('HTTP Server', 'Serve-Always'))
        self.Serve_Html       = self.toBool(self.config.get('HTTP Server', 'Serve-Html'))

        # Get raw file paths from config
        html_filename = self.config.get('HTTP Server', 'HtmlFilename')
        exe_filename = self.config.get('HTTP Server', 'ExeFilename')

        # Resolve paths based on config source
        if not os.path.isabs(html_filename):
            if getattr(self.config, '_is_user_config', False):
                # User config: relative to cwd
                self.Html_Filename = str(Path.cwd() / html_filename)
            else:
                # Default config: relative to package
                self.Html_Filename = os.path.join(os.path.dirname(__file__), html_filename)
        else:
            self.Html_Filename = html_filename

        if not os.path.isabs(exe_filename):
            if getattr(self.config, '_is_user_config', False):
                # User config: relative to cwd
                self.Exe_Filename = str(Path.cwd() / exe_filename)
            else:
                # Default config: relative to package
                self.Exe_Filename = os.path.join(os.path.dirname(__file__), exe_filename)
        else:
            self.Exe_Filename = exe_filename

        self.Exe_DlName       = self.config.get('HTTP Server', 'ExeDownloadName')
        self.WPAD_Script      = self.config.get('HTTP Server', 'WPADScript')
        self.HtmlToInject     = self.config.get('HTTP Server', 'HTMLToInject')

        if len(self.HtmlToInject) == 0:
            self.HtmlToInject = ""  # Let users set it up themself in Responder.conf. "<img src='file://///"+self.Bind_To+"/pictures/logo.jpg' alt='Loading' height='1' width='1'>"

        if len(self.WPAD_Script) == 0:
            if self.WPAD_On_Off:
                self.WPAD_Script = (
                    'function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; return "PROXY '
                    + self.Bind_To
                    + ':3128; DIRECT";}'
                )

            if self.ProxyAuth_On_Off:
                self.WPAD_Script = (
                    'function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; return "PROXY '
                    + self.Bind_To
                    + ':3128; DIRECT";}'
                )

        # Validate file existence for HTTP serving options
        if self.Serve_Exe == True:
            if not os.path.exists(self.Html_Filename):
                print(
                    utils.color(
                        "/!\\ Warning: %s: file not found" % self.Html_Filename, 3, 1
                    )
                )

            if self.Exe_Filename and not os.path.exists(self.Exe_Filename):
                print(
                    utils.color(
                        "/!\\ Warning: %s: file not found" % self.Exe_Filename, 3, 1
                    )
                )

        # SSL Options - resolve paths based on config source
        ssl_key = self.config.get("HTTPS Server", "SSLKey")
        ssl_cert = self.config.get("HTTPS Server", "SSLCert")

        # Resolve SSL paths based on config source
        if not os.path.isabs(ssl_key):
            if getattr(self.config, '_is_user_config', False):
                # User config: relative to cwd
                self.SSLKey = str(Path.cwd() / ssl_key)
            else:
                # Default config: relative to package
                self.SSLKey = os.path.join(os.path.dirname(__file__), ssl_key)
        else:
            self.SSLKey = ssl_key

        if not os.path.isabs(ssl_cert):
            if getattr(self.config, '_is_user_config', False):
                # User config: relative to cwd
                self.SSLCert = str(Path.cwd() / ssl_cert)
            else:
                # Default config: relative to package
                self.SSLCert = os.path.join(os.path.dirname(__file__), ssl_cert)
        else:
            self.SSLCert = ssl_cert

        # Respond to hosts
        self.RespondTo = list(
            filter(
                None,
                [
                    x.upper().strip()
                    for x in self.config.get("Responder Core", "RespondTo")
                    .strip()
                    .split(",")
                ],
            )
        )
        self.RespondToName = list(
            filter(
                None,
                [
                    x.upper().strip()
                    for x in self.config.get("Responder Core", "RespondToName")
                    .strip()
                    .split(",")
                ],
            )
        )
        self.DontRespondTo = list(
            filter(
                None,
                [
                    x.upper().strip()
                    for x in self.config.get("Responder Core", "DontRespondTo")
                    .strip()
                    .split(",")
                ],
            )
        )
        self.DontRespondToTLD = list(
            filter(
                None,
                [
                    x.upper().strip()
                    for x in self.config.get("Responder Core", "DontRespondToTLD")
                    .strip()
                    .split(",")
                ],
            )
        )
        self.DontRespondToName_ = list(
            filter(
                None,
                [
                    x.upper().strip()
                    for x in self.config.get("Responder Core", "DontRespondToName")
                    .strip()
                    .split(",")
                ],
            )
        )
        # add a .local to all provided DontRespondToName
        self.MDNSTLD = [".LOCAL"]
        self.DontRespondToName = [
            x + y for x in self.DontRespondToName_ for y in [""] + self.MDNSTLD
        ]
        # Generate Random stuff for one Responder session
        self.MachineName = "WIN-" + "".join(
            [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for i in range(11)]
        )
        self.Username = "".join(
            [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for i in range(6)]
        )
        self.Domain = "".join(
            [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for i in range(4)]
        )
        self.DHCPHostname = "".join(
            [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for i in range(9)]
        )
        self.DomainName = self.Domain + ".LOCAL"
        self.MachineNego = (
            "".join(
                [
                    random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                    for i in range(9)
                ]
            )
            + "$@"
            + self.DomainName
        )
        self.RPCPort = random.randrange(45000, 49999)
        # Auto Ignore List
        self.AutoIgnore = self.toBool(
            self.config.get("Responder Core", "AutoIgnoreAfterSuccess")
        )
        self.CaptureMultipleCredentials = self.toBool(
            self.config.get("Responder Core", "CaptureMultipleCredentials")
        )
        self.CaptureMultipleHashFromSameHost = self.toBool(
            self.config.get("Responder Core", "CaptureMultipleHashFromSameHost")
        )
        self.AutoIgnoreList = []

        # Set up Challenge
        self.NumChal = self.config.get("Responder Core", "Challenge")
        if self.NumChal.lower() == "random":
            self.NumChal = "random"

        if len(self.NumChal) != 16 and self.NumChal != "random":
            print(
                utils.color(
                    "[!] The challenge must be exactly 16 chars long.\nExample: 1122334455667788",
                    1,
                )
            )
            sys.exit(-1)

        self.Challenge = b""
        if self.NumChal.lower() == "random":
            pass
        else:
            if self.PY2OR3 == "PY2":
                for i in range(0, len(self.NumChal), 2):
                    self.Challenge += self.NumChal[i : i + 2].decode("hex")
            else:
                self.Challenge = bytes.fromhex(self.NumChal)

        # Set up logging
        logging.basicConfig(
            filename=self.SessionLogFile,
            level=logging.INFO,
            format="%(asctime)s - %(message)s",
            datefmt="%m/%d/%Y %I:%M:%S %p",
        )
        logging.warning("Responder Started: %s" % self.CommandLine)

        Formatter = logging.Formatter("%(asctime)s - %(message)s")
        PLog_Handler = logging.FileHandler(self.PoisonersLogFile, "w")
        ALog_Handler = logging.FileHandler(self.AnalyzeLogFile, "a")
        PLog_Handler.setLevel(logging.INFO)
        ALog_Handler.setLevel(logging.INFO)
        PLog_Handler.setFormatter(Formatter)
        ALog_Handler.setFormatter(Formatter)

        self.PoisonersLogger = logging.getLogger("Poisoners Log")
        self.PoisonersLogger.addHandler(PLog_Handler)

        self.AnalyzeLogger = logging.getLogger("Analyze Log")
        self.AnalyzeLogger.addHandler(ALog_Handler)

        # First time Responder run?
        if os.path.isfile(LOGS_PATH / "Responder.db"):
            pass
        else:
            # If it's the first time, generate SSL certs for this Responder session and send openssl output to /dev/null
            Certs = os.system("certs/gen-self-signed-cert.sh >/dev/null 2>&1")

        try:
            NetworkCard = subprocess.check_output(["ifconfig", "-a"])
        except:
            try:
                NetworkCard = subprocess.check_output(["ip", "address", "show"])
            except subprocess.CalledProcessError as ex:
                NetworkCard = "Error fetching Network Interfaces:", ex
                pass
        try:
            p = subprocess.Popen(
                "resolvectl", stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            DNS = p.stdout.read()
        except:
            p = subprocess.Popen(
                ["cat", "/etc/resolv.conf"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            DNS = p.stdout.read()

        try:
            RoutingInfo = subprocess.check_output(["netstat", "-rn"])
        except:
            try:
                RoutingInfo = subprocess.check_output(["ip", "route", "show"])
            except subprocess.CalledProcessError as ex:
                RoutingInfo = "Error fetching Routing information:", ex
                pass

        Message = (
            "%s\nCurrent environment is:\nNetwork Config:\n%s\nDNS Settings:\n%s\nRouting info:\n%s\n\n"
            % (
                utils.HTTPCurrentDate(),
                NetworkCard.decode("latin-1"),
                DNS.decode("latin-1"),
                RoutingInfo.decode("latin-1"),
            )
        )
        try:
            utils.DumpConfig(self.ResponderConfigDump, Message)
            # utils.DumpConfig(self.ResponderConfigDump,str(self))
        except AttributeError as ex:
            print("Missing Module:", ex)
            pass


# Create a singleton instance that can be imported directly
Config = Settings()
