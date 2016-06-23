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
