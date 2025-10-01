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
from binascii import hexlify
from pyasn1.codec.ber.decoder import decode

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler


class SNMP(BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        received_record, rest_of_substrate = decode(data)

        snmp_version = int(received_record["field-0"])

        if snmp_version == 3:
            full_snmp_msg = hexlify(data).decode("utf-8")
            received_record_inner, _ = decode(received_record["field-2"])
            snmp_user = str(received_record_inner["field-3"])
            engine_id = hexlify(received_record_inner["field-0"]._value).decode("utf-8")
            auth_params = hexlify(received_record_inner["field-4"]._value).decode(
                "utf-8"
            )

            SaveToDb(
                {
                    "module": "SNMP",
                    "type": "SNMPv3",
                    "client": self.client_address[0],
                    "user": snmp_user,
                    "hash": auth_params,
                    "fullhash": "{}:{}:{}:{}".format(
                        snmp_user, full_snmp_msg, engine_id, auth_params
                    ),
                }
            )
        else:
            community_string = str(received_record["field-1"])
            snmp_version = "1" if snmp_version == 0 else "2c"

            SaveToDb(
                {
                    "module": "SNMP",
                    "type": "Cleartext SNMPv{}".format(snmp_version),
                    "client": self.client_address[0],
                    "user": community_string,
                    "cleartext": community_string,
                    "fullhash": community_string,
                }
            )
