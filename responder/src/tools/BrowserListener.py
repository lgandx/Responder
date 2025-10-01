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
import os
import _thread

BASEDIR = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASEDIR)

from servers.Browser import (
    WorkstationFingerPrint,
    RequestType,
    RAPThisDomain,
    RapFinger,
)
from socketserver import UDPServer, ThreadingMixIn, BaseRequestHandler
from threading import Lock
from responder.src.utils import *


def ParseRoles(data):
    if len(data) != 4:
        return ""

    AllRoles = {
        "Workstation": (ord(data[0]) >> 0) & 1,
        "Server": (ord(data[0]) >> 1) & 1,
        "SQL": (ord(data[0]) >> 2) & 1,
        "Domain Controller": (ord(data[0]) >> 3) & 1,
        "Backup Controller": (ord(data[0]) >> 4) & 1,
        "Time Source": (ord(data[0]) >> 5) & 1,
        "Apple": (ord(data[0]) >> 6) & 1,
        "Novell": (ord(data[0]) >> 7) & 1,
        "Member": (ord(data[1]) >> 0) & 1,
        "Print": (ord(data[1]) >> 1) & 1,
        "Dialin": (ord(data[1]) >> 2) & 1,
        "Xenix": (ord(data[1]) >> 3) & 1,
        "NT Workstation": (ord(data[1]) >> 4) & 1,
        "WfW": (ord(data[1]) >> 5) & 1,
        "Unused": (ord(data[1]) >> 6) & 1,
        "NT Server": (ord(data[1]) >> 7) & 1,
        "Potential Browser": (ord(data[2]) >> 0) & 1,
        "Backup Browser": (ord(data[2]) >> 1) & 1,
        "Master Browser": (ord(data[2]) >> 2) & 1,
        "Domain Master Browser": (ord(data[2]) >> 3) & 1,
        "OSF": (ord(data[2]) >> 4) & 1,
        "VMS": (ord(data[2]) >> 5) & 1,
        "Windows 95+": (ord(data[2]) >> 6) & 1,
        "DFS": (ord(data[2]) >> 7) & 1,
        "Local": (ord(data[3]) >> 6) & 1,
        "Domain Enum": (ord(data[3]) >> 7) & 1,
    }

    return ", ".join(k for k, v in list(AllRoles.items()) if v == 1)


class BrowserListener(BaseRequestHandler):
    def handle(self):
        data, socket = self.request

        lock = Lock()
        lock.acquire()

        DataOffset = struct.unpack("<H", data[139:141])[0]
        BrowserPacket = data[82 + DataOffset :]
        ReqType = RequestType(BrowserPacket[0])

        Domain = Decode_Name(data[49:81])
        Name = Decode_Name(data[15:47])
        Role1 = NBT_NS_Role(data[45:48])
        Role2 = NBT_NS_Role(data[79:82])
        Fprint = WorkstationFingerPrint(data[190:192])
        Roles = ParseRoles(data[192:196])

        print(text("[BROWSER] Request Type : %s" % ReqType))
        print(text("[BROWSER] Address      : %s" % self.client_address[0]))
        print(text("[BROWSER] Domain       : %s" % Domain))
        print(text("[BROWSER] Name         : %s" % Name))
        print(text("[BROWSER] Main Role    : %s" % Role1))
        print(text("[BROWSER] 2nd Role     : %s" % Role2))
        print(text("[BROWSER] Fingerprint  : %s" % Fprint))
        print(text("[BROWSER] Role List    : %s" % Roles))

        RAPThisDomain(self.client_address[0], Domain)

        lock.release()


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        self.allow_reuse_address = 1
        UDPServer.server_bind(self)


def serve_thread_udp_broadcast(host, port, handler):
    try:
        server = ThreadingUDPServer(("", port), handler)
        server.serve_forever()
    except:
        print(
            "Error starting UDP server on port "
            + str(port)
            + ", check permissions or other servers running."
        )


if __name__ == "__main__":
    try:
        print("Listening for BROWSER datagrams...")
        _thread.start_new(serve_thread_udp_broadcast, ("", 138, BrowserListener))

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        sys.exit("\r Exiting...")
