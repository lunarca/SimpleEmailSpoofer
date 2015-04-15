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

            if spf.all_string is not None:
                if spf.all_string == "~all" or spf.all_string == "-all":
                    meh("SPF record contains an All item: " + spf.all_string)
                else:
                    good("SPF record All item is too weak: " + spf.all_string)
                    spoofable = True
            else:
                good("SPF record has no All string")

        except NoSpfRecordException:
            good( domain + " has no SPF record!")
            spoofable = True

        try:
            dmarc = get_dmarc(domain)
            info("Found DMARC record:")
            info(str(dmarc))

            if dmarc.policy is not None:
                if not dmarc.policy == "reject" and not dmarc.policy == "quarantine":
                    spoofable = True
                    good("DMARC policy set to " + dmarc.policy)
                else:
                    bad("DMARC policy set to " + dmarc.policy)

            else:
                good("DMARC record has no Policy")
                spoofable = True

            if dmarc.pct is not None and dmarc.pct != str(100):
                meh("DMARC pct is set to " + dmarc.pct +"% - might be possible")

            if dmarc.rua is not None:
                meh("Aggregate reports will be sent: " + dmarc.rua)

            if dmarc.ruf is not None:
                meh("Forensics reports will be sent: " + dmarc.ruf)


        except NoDmarcRecordException:
            good( domain + " has no DMARC record!")
            spoofable = True

        if spoofable:
            good( "Spoofing possible for " + domain + "!")
        else:
            bad( "Spoofing not possible for " + domain)


    except IndexError:
        error("Usage: " + sys.argv[0] + " [DOMAIN]")