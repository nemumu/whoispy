from abc import *
import re

class parser_base(metaclass=ABCMeta):

    def __init__(self, rawData):
        self.rawData = rawData

    @abstractmethod
    def domainName(self):
        pass

    @abstractmethod
    def registryDomainID(self):
        pass

    @abstractmethod
    def registrarWHOISServer(self):
        pass

    @abstractmethod
    def registrarURL(self):
        pass

    @abstractmethod
    def updatedDate(self):
        pass

    @abstractmethod
    def creationDate(self):
        pass

    @abstractmethod
    def registrarRegistrationExpirationDate(self):
        pass

    @abstractmethod
    def registrar(self):
        pass

    @abstractmethod
    def registrarIANAID(self):
        pass

    @abstractmethod
    def domainStatus(self):
        pass

    @abstractmethod
    def registryRegistrantID(self):
        pass

    @abstractmethod
    def registrantName(self):
        pass

    @abstractmethod
    def registrantOrganization(self):
        pass

    @abstractmethod
    def registrantStreet(self):
        pass

    @abstractmethod
    def registrantCity(self):
        pass

    @abstractmethod
    def registrantStateProvince(self):
        pass

    @abstractmethod
    def registrantPostalCode(self):
        pass

    @abstractmethod
    def registrantCountry(self):
        pass

    @abstractmethod
    def registrantPhone(self):
        pass

    @abstractmethod
    def registrantPhoneExt(self):
        pass

    @abstractmethod
    def registrantFax(self):
        pass

    @abstractmethod
    def registrantFaxExt(self):
        pass

    @abstractmethod
    def registrantEmail(self):
        pass

    @abstractmethod
    def registryAdminID(self):
        pass

    @abstractmethod
    def adminName(self):
        pass

    @abstractmethod
    def adminOrganization(self):
        pass

    @abstractmethod
    def adminStreet(self):
        pass

    @abstractmethod
    def adminCity(self):
        pass

    @abstractmethod
    def adminStateProvince(self):
        pass

    @abstractmethod
    def adminPostalCode(self):
        pass

    @abstractmethod
    def adminCountry(self):
        pass

    @abstractmethod
    def adminPhone(self):
        pass

    @abstractmethod
    def adminPhoneExt(self):
        pass

    @abstractmethod
    def adminFax(self):
        pass

    @abstractmethod
    def adminFaxExt(self):
        pass

    @abstractmethod
    def adminEmail(self):
        pass

    @abstractmethod
    def registryTechID(self):
        pass

    @abstractmethod
    def techName(self):
        pass

    @abstractmethod
    def techOrganization(self):
        pass

    @abstractmethod
    def techStreet(self):
        pass

    @abstractmethod
    def techCity(self):
        pass

    @abstractmethod
    def techStateProvince(self):
        pass

    @abstractmethod
    def techPostalCode(self):
        pass

    @abstractmethod
    def techCountry(self):
        pass

    @abstractmethod
    def techPhone(self):
        pass

    @abstractmethod
    def techPhoneExt(self):
        pass

    @abstractmethod
    def techFax(self):
        pass

    @abstractmethod
    def techFaxExt(self):
        pass

    @abstractmethod
    def techEmail(self):
        pass

    @abstractmethod
    def nameServer(self):
        pass

    @abstractmethod
    def DNSSEC(self):
        pass

    @abstractmethod
    def registrarAbuseContactEmail(self):
        pass

    @abstractmethod
    def registrarAbuseContactPhone(self):
        pass

    @abstractmethod
    def urlOfTheICANNWHOISDataProblemReportingSystem(self):
        pass
