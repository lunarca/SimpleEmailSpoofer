# SimpleEmailSpoofer
A few Python programs designed to help penetration testers with email spoofing.

## `SimpleEmailSpoofer.py`
A program that spoofs emails. Currently in development

## `spoofcheck.py`
A program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing. 

Additionally it will alert if the domain has DMARC configuration that sends mail or HTTP requests on failed SPF/DKIM emails.

Usage:

	./spoofcheck.py [DOMAIN]


## Dependencies
- `dnspython`
- `colorama`