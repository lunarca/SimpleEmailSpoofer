# SimpleEmailSpoofer
A few Python programs designed to help penetration testers with email spoofing.

## Setup

### Mail Server
Email servers do not accept connections from normal computers. In an effort to limit the amount of spam, 
most MTAs will only accept connections from relays that have a fully-qualified domain name (FQDN). 
As such, the easiest way to use this project is from a Linux Virtual Private Server. There are several
free or cheap options available, such as Digital Ocean, Linode, and Amazon EC2.

Once the server is set up, the next step is to install and start an SMTP server. This is required to actually send
the spoofed emails. I personally use Postfix, though any will do. This script defaults to using localhost:25
for the mail server.

On Kali Linux, the easiest method of doing this is:

`sudo apt-get install postfix`
`sudo service postfix start`

When installing postfix, specify `Internet-facing` and provide the correct FQDN when prompted.

### Dependencies
This script has two dependencies:

- `dnspython`
- `colorama`

These can be installed using pip:

`pip install -r requirements.txt`

## Basic Usage

Add the desired contents of the email in HTML format to an HTML file. Then, execute the following command: 

`./SimpleEmailSpoofer.py -e [Path to Email file] -t [To address] -f [From address] -n [From name] -j [Email subject]`

Additional flags can be found by running

`./SimpleEmailSpoofer.py -h`

# Email Spoofing 101

## Basic Principles
Email spoofing has been an issue since the earliest days of the SMTP protocol. The root cause of email spoofing is that SMTP  does not require authentication between mail relays. An attacker can stand up or find an "Open Relay" (i.e. an SMTP server that can send from arbitrary domains), which is the default configuration for SMTP servers, and use that to send arbitrary emails from arbitrary email addresses.

## FQDN Requirements
In an effort to combat spam, many SMTP servers now block any mail relay that does not have a Fully-qualified Domain Name (FQDN). An FQDN is a DNS A record that points to the relay's IP address. This can be either a domain purchased from a domain registrar, or by using a domain automatically associated with a virtual private server. 

## Email Protections
As email spoofing is a serious and widespread issue, over the years several protection mechanisms have been added to combat it. However, all of these protections are opt-in and require significant configuration. As such, as much as 98% of the internet is still vulnerable. For additional information, please see [the Bishop Fox blog post on the subject](https://www.bishopfox.com/blog/2017/05/how-we-can-stop-email-spoofing/). 

To determine if a domain is vulnerable to email spoofing, Bishop Fox has created two tools:
* A [web interface](http://spoofcheck.bishopfox.com) that produces a report with analysis and recommendations
* A [command line utility](https://github.com/bishopfox/spoofcheck) that only performs analysis

# Disclaimer
Only use this tool for education, research, or in the course of approved social engineering assessments. While email spoofing is a powerful tool in the social engineer's arsenal, it is also trivial to identify the server that sent any email. Furthermore, this tool makes no claims to bypass any products such as Barracuda or ForcePoint email protections suites. Please use responsibly.

# Spoofcheck
The Spoofcheck program, which allows users to identify whether or not domains are vulnerable to email spoofing, has moved to the following repository:

[https://github.com/bishopfox/spoofcheck](https://github.com/bishopfox/spoofcheck)
