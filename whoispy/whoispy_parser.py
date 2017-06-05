from abc import *
import re

class parser_base(metaclass=ABCMeta):
    @abstractmethod
    def domadinName():
        pass

    @abstractmethod
    def registryDomainID():
        pass

    @abstractmethod
    def registrarWHOISServer():
        pass

    @abstractmethod
    def registrarURL():
        pass

    @abstractmethod
    def updatedDate():
        pass

    @abstractmethod
    def creationDate():
        pass

    @abstractmethod
    def registrarRegistrationExpirationDate():
        pass

    @abstractmethod
    def registrar():
        pass

    @abstractmethod
    def registrarIANAID():
        pass

    @abstractmethod
    def domainStatus():
        pass

    @abstractmethod
    def registryRegistrantID():
        pass

    @abstractmethod
    def registrantName():
        pass

    @abstractmethod
    def registrantOrganization():
        pass

    @abstractmethod
    def registrantStreet():
        pass

    @abstractmethod
    def registrantCity():
        pass

    @abstractmethod
    def registrantStateProvince():
        pass

    @abstractmethod
    def registrantPostalCode():
        pass

    @abstractmethod
    def registrantCountry():
        pass

    @abstractmethod
    def registrantPhone():
        pass

    @abstractmethod
    def registrantPhoneExt():
        pass

    @abstractmethod
    def registrantFax():
        pass

    @abstractmethod
    def registrantFaxExt():
        pass

    @abstractmethod
    def registrantEmail():
        pass

    @abstractmethod
    def registryAdminID():
        pass

    @abstractmethod
    def adminName():
        pass

    @abstractmethod
    def adminOrganization():
        pass

    @abstractmethod
    def adminStreet():
        pass

    @abstractmethod
    def adminCity():
        pass

    @abstractmethod
    def adminStateProvince():
        pass

    @abstractmethod
    def adminPostalCode():
        pass

    @abstractmethod
    def adminCountry():
        pass

    @abstractmethod
    def adminPhone():
        pass

    @abstractmethod
    def adminPhoneExt():
        pass

    @abstractmethod
    def adminFax():
        pass

    @abstractmethod
    def adminFaxExt():
        pass

    @abstractmethod
    def adminEmail():
        pass

    @abstractmethod
    def registryTechID():
        pass

    @abstractmethod
    def techName():
        pass

    @abstractmethod
    def techOrganization():
        pass

    @abstractmethod
    def techStreet():
        pass

    @abstractmethod
    def techCity():
        pass

    @abstractmethod
    def techStateProvince():
        pass

    @abstractmethod
    def techPostalCode():
        pass

    @abstractmethod
    def techCountry():
        pass

    @abstractmethod
    def techPhone():
        pass

    @abstractmethod
    def techPhoneExt():
        pass

    @abstractmethod
    def techFax():
        pass

    @abstractmethod
    def techFaxExt():
        pass

    @abstractmethod
    def techEmail():
        pass

    @abstractmethod
    def nameServer():
        pass

    @abstractmethod
    def DNSSEC():
        pass

    @abstractmethod
    def registrarAbuseContactEmail():
        pass

    @abstractmethod
    def registrarAbuseContactPhone():
        pass

    @abstractmethod
    def urlOfTheICANNWHOISDataProblemReportingSystem():
        pass

def parse(raw_data, tld_addr):
    if tld_addr == "whois.aero":
        return aero_parser(raw_data)
    elif tld_addr == "whois.iana.org":
        return arpa_parser(raw_data)
    elif tld_addr == "whois.nic.asia":
        return asia_parser(raw_data)
    elif tld_addr == "whois.biz":
        return biz_parser(raw_data)
    elif tld_addr == "whois.cat":
        return cat_parser(raw_data)
    elif tld_addr == "whois.verisign-grs.com":
        return com_parser(raw_data)
    else:
        return -1

def aero_parser(raw_data):
    return regex_support(raw_data, "Access ")

def arpa_parser(raw_data):
    return regex_support(raw_data, "% This query returned 1 objects.")

def asia_parser(raw_data):
    return regex_support(raw_data, "DotAsia ")

def biz_parser(raw_data):
    return regex_support(raw_data, "Domain ")

def cat_parser(raw_data):
    return regex_support(raw_data, "Domain ID:")

def com_parser(raw_data):
    return ~regex_support(raw_data, "No match for") + 2

def regex_support(raw_data, regex_word):
    regex = re.compile(regex_word)
    match = regex.search(raw_data)

    if match:
        return 0
    return 1
