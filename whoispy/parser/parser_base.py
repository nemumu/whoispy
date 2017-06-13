from abc import *
import re

class parser_base(metaclass=ABCMeta):

    def __init__(self, raw_data):
        self.data = raw_data

    @abstractmethod
    def domainName(self):
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
