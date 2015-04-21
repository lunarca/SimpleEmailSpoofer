#! /usr/bin/env python

import sys

from colorama import init as color_init

import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib

from libs.PrettyOutput import output_good, output_bad, \
    output_info, output_error, output_indifferent

if __name__ == "__main__":
    color_init()
    spoofable = False

    try:
        domain = sys.argv[1]

        try:
            spf = spflib.SpfRecord.from_domain(domain)
            output_info("Found SPF record:")
            output_info(str(spf))

            if spf.all_string is not None:
                if spf.all_string == "~all" or spf.all_string == "-all":
                    output_indifferent("SPF record contains an All item: " + spf.all_string)
                else:
                    output_good("SPF record All item is too weak: " + spf.all_string)
                    spoofable = True
            else:
                output_good("SPF record has no All string")

        except spflib.NoSpfRecordException:
            output_good( domain + " has no SPF record!")
            spoofable = True

        try:
            dmarc = dmarclib.DmarcRecord.from_domain(domain)
            output_info("Found DMARC record:")
            output_info(str(dmarc))

            if dmarc.policy is not None:
                if not dmarc.policy == "reject" and not dmarc.policy == "quarantine":
                    spoofable = True
                    output_good("DMARC policy set to " + dmarc.policy)
                else:
                    output_bad("DMARC policy set to " + dmarc.policy)

            else:
                output_good("DMARC record has no Policy")
                spoofable = True

            if dmarc.pct is not None and dmarc.pct != str(100):
                output_indifferent("DMARC pct is set to " + dmarc.pct + "% - might be possible")

            if dmarc.rua is not None:
                output_indifferent("Aggregate reports will be sent: " + dmarc.rua)

            if dmarc.ruf is not None:
                output_indifferent("Forensics reports will be sent: " + dmarc.ruf)

        except dmarclib.NoDmarcRecordException:
            output_good(domain + " has no DMARC record!")
            spoofable = True

        if spoofable:
            output_good("Spoofing possible for " + domain + "!")
        else:
            output_bad("Spoofing not possible for " + domain)

    except IndexError:
        output_error("Usage: " + sys.argv[0] + " [DOMAIN]")