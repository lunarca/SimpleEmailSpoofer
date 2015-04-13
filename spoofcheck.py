#! /usr/bin/env python

from libs.EmailProtectionsLib import *
from libs.PrettyOutput import *

from colorama import Fore, Back, Style
from colorama import init as color_init

import sys

if __name__ == "__main__":
    color_init()
    spoofable = False

    try:
        domain = sys.argv[1]

        try:
            spf = get_spf(domain)
            info("Found SPF record:")
            info(str(spf))

            try:
                if spf.all_string == "~all" or spf.all_string == "-all":
                    meh("SPF record contains an All item: " + spf.all_string)
                else:
                    good("SPF record All item is too weak: " + spf.all_string)
                    spoofable = True
            except AttributeError:
                good("SPF record has no All string")

        except NoSpfRecordException:
            good( domain + " has no SPF record!")
            spoofable = True

        try:
            dmarc = get_dmarc(domain)
            info("Found DMARC record:")
            info(str(dmarc))

            try:
                if not dmarc.policy == "reject" and not dmarc.policy == "quarantine":
                    spoofable = True
                    good("DMARC policy set to " + dmarc.policy)
                else:
                    bad("DMARC policy set to " + dmarc.policy)

            except AttributeError:
                good("DMARC record has no Policy")
                spoofable = True

            try:
                if dmarc.pct != str(100):
                    meh("DMARC pct is set to " + dmarc.pct +"% - might be possible")
            except: pass

            try:
                meh("Aggregate reports will be sent: " + dmarc.rua)
            except: pass

            try:
                meh("Forensics reports will be sent: " + dmarc.ruf)
            except: pass


        except NoDmarcRecordException:
            good( domain + " has no DMARC record!")
            spoofable = True

        if spoofable:
            good( "Spoofing possible for " + domain + "!")
        else:
            bad( "Spoofing not possible for " + domain)


    except IndexError:
        error("Usage: " + sys.argv[0] + " [DOMAIN]")