#! /usr/bin/env python

from libs.EmailProtectionsLib import *
from libs.PrettyOutput import *

import re
import smtplib
import argparse

from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("to_address", help="Email address to send to")
    parser.add_argument("from_address", help="Email address to send from")
    parser.add_argument("subject", nargs="?", help="Subject for the email")
    parser.add_argument("filename", nargs="?", help="Filename containing an HTML email")

    parser.add_argument("-c", "--check", dest="spoof_check", action="store_true",
        help="Check to ensure FROM domain can be spoofed from (default)", default=True)
    parser.add_argument("-x", "--nocheck", dest="spoof_check", action="store_false",
        help="Do not check that FROM domain can be spoofed from")
    parser.add_argument("-f", "--force", dest="force", action="store_true", default=False,
        help="Force the email to send despite protections")
    parser.add_argument("-n", "--from_name", dest="from_name", help="From name")


    email_options = parser.add_argument_group("Email Options")
    email_options.add_argument("-i", "--interactive", action="store_true", dest="interactive_email", 
        help="Input email in interactive mode")

    smtp_options = parser.add_argument_group("SMTP options")
    smtp_options.add_argument("-s", "--server", dest="smtp_server", 
        help="SMTP server IP or DNS name (default localhost)", default="localhost")
    smtp_options.add_argument("-p", "--port", dest="smtp_port", type=int, help="SMTP server port (default 25)", 
        default=25)

    return parser.parse_args()

def get_ack(force):
    info("To continue: [yes/no]")
    if not force:
        yn = raw_input()
        if yn != "yes":
            return False
        else:
            return True
    else:
        meh( "Forced yes")
        return True

if __name__ == "__main__":
    args = get_args()

    print args

    email_text = ""

    # Read email text into email_text
    if args.interactive_email:
        info("Enter HTML email line by line")
        info("Press CTRL+D to finish")
        while True:
            try:
                line = raw_input("| ")
                email_text += line + "\n"
            except EOFError:
                info("Email captured.")
                break
    else:
        try:
            with open(args.filename, "r") as infile:
                info("Reading " + args.filename + " as email file")
                email_text = infile.read()
        except:
            error("Could not open file " + args.filename)
            exit(-1)

    email_re = re.compile(".*@(.*\...*)")


    from_domain = email_re.match(args.from_address).group(1)
    to_domain = email_re.match(args.to_address).group(1)
    
    info("Checking if from domain " + Style.BRIGHT + from_domain + Style.NORMAL + " is spoofable")


    if from_domain == "gmail.com":
        if to_domain == "gmail.com":
            bad("You are trying to spoof from a gmail address to a gmail address.")
            bad("The Gmail web application will display a warning message on your email.")
            if not get_ack(args.force):
                bad("Exiting")
                exit(1)
        else:
            meh("You are trying to spoof from a gmail address.")
            meh("If the domain you are sending to is controlled by Google Apps the web application will display a warning message on your email.")
            if not get_ack(args.force):
                bad("Exiting")
                exit(1)

    if args.spoof_check:
        spoofable = False
        try:
            spf = get_spf(from_domain)

            try:
                if not (spf.all_string == "~all" or spf.all_string == "-all"):
                    spoofable = True
            except: pass

        except NoSpfRecordException:
            spoofable = True

        try:
            dmarc = get_dmarc(from_domain)
            info(str(dmarc))

            try:
                if not dmarc.policy == "reject" and not dmarc.policy == "quarantine":
                    spoofable = True

            except AttributeError:
                spoofable = True

            try:
                if dmarc.pct != str(100):
                    meh("DMARC pct is set to " + dmarc.pct +"% - Spoofing might be possible")
            except: pass

            try:
                meh("Aggregate reports will be sent: " + dmarc.rua)
                if not get_ack(args.force):
                    bad("Exiting")
                    exit(1)
            except: pass

            try:
                meh("Forensics reports will be sent: " + dmarc.ruf)
                if not get_ack(args.force):
                    bad("Exiting")
                    exit(1)
            except: pass


        except NoDmarcRecordException:
            spoofable = True

        if not spoofable:
            bad("From domain " + Style.BRIGHT + from_domain + Style.NORMAL + " is not spoofable.")

            if not args.force:
                bad("Exiting. (-f to override)")
                exit(2)
            else:
                meh("Overriding...")
        else:
            good("From domain " + Style.BRIGHT + from_domain + Style.NORMAL + " is spoofable!")

    info("Sending to " + args.to_address)

    # try:
    info("Connecting to SMTP server at " + args.smtp_server + ":" + str(args.smtp_port))
    server = smtplib.SMTP(args.smtp_server, args.smtp_port)
    msg = MIMEMultipart("alternative")
    msg.set_charset("utf-8")

    if args.from_name is not None:
        info("Setting From header to: " + args.from_name + "<" + args.from_address + ">")
        msg["From"] = args.from_name + "<" + args.from_address + ">"
    else:
        info("Setting From header to: " + args.from_name)
        msg["From"] = args.from_address

    if args.subject is not None:
        info("Setting Subject header to: " + args.subject)
        msg["Subject"] = args.subject

    msg.attach(MIMEText(email_text, 'html', 'utf-8'))

    info("The email in full: ")
    print msg

    if not args.force:
        bad("Exiting. (-f to override)")
        exit(2)

    server.sendmail(args.to_address, msg)

    # except Exception as e:
    #     error("Error: Could not send email to " + args.to_address )
    #     raise e
