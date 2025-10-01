#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Performs various techniques to dump hashes from the
#              remote machine without executing any agent there.
#              For SAM and LSA Secrets (including cached creds)
#              we try to read as much as we can from the registry
#              and then we save the hives in the target system
#              (%SYSTEMROOT%\\Temp dir) and read the rest of the
#              data from there.
#              For NTDS.dit we either:
#                a. Get the domain users list and get its hashes
#                   and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#                   call, replicating just the attributes we need.
#                b. Extract NTDS.dit via vssadmin executed  with the
#                   smbexec approach.
#                   It's copied on the temp dir and parsed remotely.
#
#              The script initiates the services required for its working
#              if they are not available (e.g. Remote Registry, even if it is
#              disabled). After the work is done, things are restored to the
#              original state.
#
# Author:
#  Alberto Solino (@agsolino)
#
# References: Most of the work done by these guys. I just put all
#             the pieces together, plus some extra magic.
#
# https://github.com/gentilkiwi/kekeo/tree/master/dcsync
# https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
# https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
# https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
# https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
# https://code.google.com/p/creddump/
# https://lab.mediaservice.net/code/cachedump.rb
# https://insecurety.net/?p=768
# http://www.beginningtoseethelight.org/ntsecurity/index.htm
# https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
# https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#
from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.secretsdump import (
    LocalOperations,
    SAMHashes,
    LSASecrets,
    NTDSHashes,
)

try:
    input = raw_input
except NameError:
    pass


class DumpSecrets:
    def __init__(self, remoteName, username="", password="", domain="", options=None):
        self.__useVSSMethod = False
        self.__remoteName = "LOCAL"
        self.__remoteHost = "LOCAL"
        self.__username = None
        self.__password = None
        self.__domain = None
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = None
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = None
        self.__bootkey = None
        self.__securityHive = None
        self.__samHive = None
        self.__ntdsFile = None
        self.__history = None
        self.__noLMHash = True
        self.__isRemote = False
        self.__outputFileName = None
        self.__doKerberos = None
        self.__justDC = False
        self.__justDCNTLM = False
        self.__justUser = None
        self.__pwdLastSet = None
        self.__printUserStatus = None
        self.__resumeFileName = None
        self.__canProcessSAMLSA = True
        self.__kdcHost = None
        self.__options = options

    def dump(self, sam, security, system, outfile):
        # Give proper credit.
        print(version.BANNER)
        # Start logger.
        # logger.init(False)
        logging.getLogger().setLevel(logging.INFO)
        self.__outputFileName = outfile
        # We only do local dumping, so sam, security, system.
        try:
            if self.__remoteName.upper() == "LOCAL" and self.__username == None:
                self.__isRemote = False
                self.__useVSSMethod = True
                localOperations = LocalOperations(system)
                bootKey = localOperations.getBootKey()

            if (
                self.__justDC is False
                and self.__justDCNTLM is False
                and self.__canProcessSAMLSA
            ):
                try:
                    if self.__isRemote is True:
                        SAMFileName = self.__remoteOps.saveSAM()
                    else:
                        SAMFileName = sam

                    self.__SAMHashes = SAMHashes(
                        SAMFileName, bootKey, isRemote=self.__isRemote
                    )
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    logging.error("SAM hashes extraction failed: %s" % str(e))

                try:
                    if self.__isRemote is True:
                        SECURITYFileName = self.__remoteOps.saveSECURITY()
                    else:
                        SECURITYFileName = security

                    self.__LSASecrets = LSASecrets(
                        SECURITYFileName,
                        bootKey,
                        self.__remoteOps,
                        isRemote=self.__isRemote,
                        history=self.__history,
                    )
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                    logging.error("LSA hashes extraction failed: %s" % str(e))

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer = input("Delete resume session file? [y/N] ")
                        if answer.upper() == "":
                            answer = "N"
                            break
                        elif answer.upper() == "Y":
                            answer = "Y"
                            break
                        elif answer.upper() == "N":
                            answer = "N"
                            break
                    if answer == "Y":
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info("Cleaning up... ")
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
