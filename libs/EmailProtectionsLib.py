import re
import dns.resolver
import logging

class NoSpfRecordException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class NoDmarcRecordException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class SpfRecord(object):
    def __init__(self, spf_string):
        spf_item_regex = "(?:((?:\+|-|~)?(?:a|mx|ptr|include|ip4|ip6|exists|redirect|exp|all)(?:(?::|/)?(?:\S*))?) ?)"
        spf_version_r = "^v=(spf.)"

        self.spf_string = spf_string
        self.version = re.match(spf_version_r, spf_string).group(1)
        self.items = re.findall(spf_item_regex, spf_string)

        self.all_string = None

        for item in self.items:
            if re.match(".all", item):
                self.all_string = item
            redirect = re.match("redirect=(.*)", item)
            if redirect is not None:
                try:
                    spf_string = get_spf_string(redirect.group(1))
                    self._process_redirect(spf_string)
                except NoSpfRecordException as ex:
                    logging.exception(ex)

    def _process_redirect(self, spf_string):
        spf_item_regex = "(?:((?:\+|-|~)?(?:a|mx|ptr|include|ip4|ip6|exists|redirect|exp|all)(?:(?::|/)?(?:\S*))?) ?)"
        spf_version_r = "^v=(spf.)"
        self.spf_string += " | " + spf_string
        self.version = re.match(spf_version_r, spf_string).group(1)
        self.items = re.findall(spf_item_regex, spf_string)

        for item in self.items:
            if re.match(".all", item):
                self.all_string = item
            redirect = re.match("redirect=(.*)", item)
            if redirect is not None:
                try:
                    spf_string = get_spf_string(redirect.group(1))
                    self._process_redirect(spf_string)
                except NoSpfRecordException as ex:
                    logging.exception(ex)

    def __str__(self):
        return self.spf_string

class DmarcRecord(object):
    def __init__(self, dmarc_string):
        dmarc_regex = "(\w+)=(.*?)(?:; ?|$)"

        self.dmarc_string = dmarc_string

        items = re.findall(dmarc_regex, dmarc_string)

        self.version = None
        self.policy = None
        self.pct = None
        self.rua = None
        self.ruf = None
        self.subdomain_policy = None
        self.dkim_alignment = None
        self.spf_alignment = None

        for item in items:
            prepend = item[0]
            if prepend == "v":
                self.version = item[1]
            elif prepend == "p":
                self.policy = item[1]
            elif prepend == "pct":
                self.pct = item[1]
            elif prepend == "rua":
                self.rua = item[1]
            elif prepend == "ruf":
                self.ruf = item[1]
            elif prepend == "sp":
                self.subdomain_policy = item[1]
            elif prepend == "adkim":
                self.dkim_alignment = item[1]
            elif prepend == "aspf":
                self.spf_alignment = item[1]
    
    def __str__(self):
        return self.dmarc_string


def get_spf(domain):
    try:
        spf_string = get_spf_string(domain)
        return SpfRecord(spf_string)
    except NoSpfRecordException as e: 
        raise

def get_dmarc(domain):
    try:
        dmarc_string = get_dmarc_string(domain)
        return DmarcRecord(dmarc_string)
    except NoDmarcRecordException as e:
        raise

def get_spf_string(domain):
    spf_re = re.compile('^"(v=spf.*)"')
    try:
        for answer in dns.resolver.query(domain, "TXT"):
            match = spf_re.match(str(answer))
            if match is not None:
                return match.group(1)
    except dns.resolver.NoAnswer:
        raise NoSpfRecordException("Domain " + domain + " did not respond to TXT query")
    except:
        raise NoSpfRecordException("Domain " + domain + " had a strange error")
    raise NoSpfRecordException("Domain " + domain + " had no SPF record")

def get_dmarc_string(domain):
    dmarc_re = re.compile('^"(v=DMARC.*)"')
    try:
        for answer in dns.resolver.query("_dmarc." + domain, "TXT"):
            match = dmarc_re.match(str(answer))
            if match is not None:
                return match.group(1)
    except dns.resolver.NoAnswer:
        raise NoDmarcRecordException("Domain " + domain + " did not respond to TXT query")
    except:
        raise NoDmarcRecordException("Domain " + domain + " had a strange error")
    raise NoDmarcRecordException("Domain " + domain + " had no DMARC record")
