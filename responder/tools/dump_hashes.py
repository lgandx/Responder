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

"""
Responder Hash Dumper

This utility extracts captured hashes from the Responder database and saves them
in John the Ripper compatible format.
"""

import sqlite3
import sys
import os
from pathlib import Path
from responder.src import settings


def DumpHashToFile(outfile, data):
    """Save hash data to file in centralized logging directory"""
    output_path = settings.LOGS_PATH / outfile
    try:
        with open(output_path, "w") as dump:
            dump.write(data)
        return output_path
    except Exception as e:
        print(f"❌ Error writing to {output_path}: {e}")
        return None


def DbConnect():
    """Connect to centralized Responder database"""
    db_path = settings.LOGS_PATH / "Responder.db"
    if not db_path.exists():
        print(f"❌ Database not found: {db_path}")
        print("💡 Run responder first to capture some hashes!")
        sys.exit(1)

    try:
        cursor = sqlite3.connect(db_path)
        return cursor
    except Exception as e:
        print(f"❌ Error connecting to database: {e}")
        sys.exit(1)


def GetResponderCompleteNTLMv2Hash(cursor):
    """Extract all NTLMv2 hashes from database"""
    try:
        res = cursor.execute(
            "SELECT fullhash FROM responder WHERE type LIKE '%v2%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM responder)"
        )
        Output = ""
        for row in res.fetchall():
            if "$" in row[0]:  # Skip machine accounts
                pass
            else:
                Output += "{0}\n".format(row[0])
        return Output
    except Exception as e:
        print(f"❌ Error querying NTLMv2 hashes: {e}")
        return ""


def GetResponderCompleteNTLMv1Hash(cursor):
    """Extract all NTLMv1 hashes from database"""
    try:
        res = cursor.execute(
            "SELECT fullhash FROM responder WHERE type LIKE '%v1%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM responder)"
        )
        Output = ""
        for row in res.fetchall():
            if "$" in row[0]:  # Skip machine accounts
                pass
            else:
                Output += "{0}\n".format(row[0])
        return Output
    except Exception as e:
        print(f"❌ Error querying NTLMv1 hashes: {e}")
        return ""


def main():
    """Main hash dumping function"""
    print("🔍 Responder Hash Dumper")
    print("=" * 40)

    cursor = DbConnect()
    print(f"✅ Connected to database: {settings.LOGS_PATH / 'Responder.db'}")
    print()

    # Dump NTLMv2 hashes
    print("🔓 Dumping NTLMv2 hashes:")
    v2 = GetResponderCompleteNTLMv2Hash(cursor)
    if v2.strip():
        v2_path = DumpHashToFile("DumpNTLMv2.txt", v2)
        if v2_path:
            print(f"✅ Saved {len(v2.strip().split())} NTLMv2 hashes to: {v2_path}")
            print("📝 Hash preview:")
            for line in v2.strip().split("\n")[:3]:  # Show first 3 hashes
                print(f"   {line}")
            if len(v2.strip().split("\n")) > 3:
                print(f"   ... and {len(v2.strip().split('\n')) - 3} more")
        else:
            print("❌ Failed to save NTLMv2 hashes")
    else:
        print("❌ No NTLMv2 hashes found.")

    print()

    # Dump NTLMv1 hashes
    print("🔓 Dumping NTLMv1 hashes:")
    v1 = GetResponderCompleteNTLMv1Hash(cursor)
    if v1.strip():
        v1_path = DumpHashToFile("DumpNTLMv1.txt", v1)
        if v1_path:
            print(f"✅ Saved {len(v1.strip().split())} NTLMv1 hashes to: {v1_path}")
            print("📝 Hash preview:")
            for line in v1.strip().split("\n")[:3]:  # Show first 3 hashes
                print(f"   {line}")
            if len(v1.strip().split("\n")) > 3:
                print(f"   ... and {len(v1.strip().split('\n')) - 3} more")
        else:
            print("❌ Failed to save NTLMv1 hashes")
    else:
        print("❌ No NTLMv1 hashes found.")

    cursor.close()
    print()
    print("✅ Hash extraction complete!")
    print(f"📁 All files saved to: {settings.LOGS_PATH}")


if __name__ == "__main__":
    main()
