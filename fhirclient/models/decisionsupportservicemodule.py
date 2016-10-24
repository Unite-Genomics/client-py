#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Generated from FHIR 1.7.0.10061 (http://hl7.org/fhir/StructureDefinition/DecisionSupportServiceModule) on 2016-10-24.
#  2016, SMART Health IT.


from . import domainresource

class DecisionSupportServiceModule(domainresource.DomainResource):
    """ A description of decision support service functionality.
    
    The DecisionSupportServiceModule describes a unit of decision support
    functionality that is made available as a service, such as immunization
    modules or drug-drug interaction checking.
    """
    
    resource_name = "DecisionSupportServiceModule"
    
    def __init__(self, jsondict=None, strict=True):
        """ Initialize all valid properties.
        
        :raises: FHIRValidationError on validation errors, unless strict is False
        :param dict jsondict: A JSON dictionary to use for initialization
        :param bool strict: If True (the default), invalid variables will raise a TypeError
        """
        
        self.approvalDate = None
        """ When decision support service module approved by publisher.
        Type `FHIRDate` (represented as `str` in JSON). """
        
        self.contact = None
        """ Contact details for the publisher.
        List of `ContactDetail` items (represented as `dict` in JSON). """
        
        self.contributor = None
        """ A content contributor.
        List of `Contributor` items (represented as `dict` in JSON). """
        
        self.copyright = None
        """ Use and/or publishing restrictions.
        Type `str`. """
        
        self.dataRequirement = None
        """ Data requirements for the module.
        List of `DataRequirement` items (represented as `dict` in JSON). """
        
        self.date = None
        """ Date this was last changed.
        Type `FHIRDate` (represented as `str` in JSON). """
        
        self.description = None
        """ Natural language description of the decision support service module.
        Type `str`. """
        
        self.effectivePeriod = None
        """ The effective date range for the decision support service module.
        Type `Period` (represented as `dict` in JSON). """
        
        self.experimental = None
        """ If for testing purposes, not real usage.
        Type `bool`. """
        
        self.identifier = None
        """ Additional identifier for the decision support service module.
        List of `Identifier` items (represented as `dict` in JSON). """
        
        self.jurisdiction = None
        """ Intended jurisdiction for decision support service module (if
        applicable).
        List of `CodeableConcept` items (represented as `dict` in JSON). """
        
        self.lastReviewDate = None
        """ Last review date for the decision support service module.
        Type `FHIRDate` (represented as `str` in JSON). """
        
        self.name = None
        """ Name for this decision support service module (Computer friendly).
        Type `str`. """
        
        self.parameter = None
        """ Parameters to the module.
        List of `ParameterDefinition` items (represented as `dict` in JSON). """
        
        self.publisher = None
        """ Name of the publisher (Organization or individual).
        Type `str`. """
        
        self.purpose = None
        """ Why this decision support service module is defined.
        Type `str`. """
        
        self.relatedArtifact = None
        """ Related resources for the module.
        List of `RelatedArtifact` items (represented as `dict` in JSON). """
        
        self.status = None
        """ draft | active | retired.
        Type `str`. """
        
        self.title = None
        """ Name for this decision support service module (Human friendly).
        Type `str`. """
        
        self.topic = None
        """ Descriptional topics for the module.
        List of `CodeableConcept` items (represented as `dict` in JSON). """
        
        self.trigger = None
        """ "when" the module should be invoked.
        List of `TriggerDefinition` items (represented as `dict` in JSON). """
        
        self.url = None
        """ Logical uri to reference this decision support service module
        (globally unique).
        Type `str`. """
        
        self.usage = None
        """ Describes the clinical usage of the module.
        Type `str`. """
        
        self.useContext = None
        """ Content intends to support these contexts.
        List of `UsageContext` items (represented as `dict` in JSON). """
        
        self.version = None
        """ Business version of the decision support service module.
        Type `str`. """
        
        super(DecisionSupportServiceModule, self).__init__(jsondict=jsondict, strict=strict)
    
    def elementProperties(self):
        js = super(DecisionSupportServiceModule, self).elementProperties()
        js.extend([
            ("approvalDate", "approvalDate", fhirdate.FHIRDate, False, None, False),
            ("contact", "contact", contactdetail.ContactDetail, True, None, False),
            ("contributor", "contributor", contributor.Contributor, True, None, False),
            ("copyright", "copyright", str, False, None, False),
            ("dataRequirement", "dataRequirement", datarequirement.DataRequirement, True, None, False),
            ("date", "date", fhirdate.FHIRDate, False, None, False),
            ("description", "description", str, False, None, False),
            ("effectivePeriod", "effectivePeriod", period.Period, False, None, False),
            ("experimental", "experimental", bool, False, None, False),
            ("identifier", "identifier", identifier.Identifier, True, None, False),
            ("jurisdiction", "jurisdiction", codeableconcept.CodeableConcept, True, None, False),
            ("lastReviewDate", "lastReviewDate", fhirdate.FHIRDate, False, None, False),
            ("name", "name", str, False, None, False),
            ("parameter", "parameter", parameterdefinition.ParameterDefinition, True, None, False),
            ("publisher", "publisher", str, False, None, False),
            ("purpose", "purpose", str, False, None, False),
            ("relatedArtifact", "relatedArtifact", relatedartifact.RelatedArtifact, True, None, False),
            ("status", "status", str, False, None, True),
            ("title", "title", str, False, None, False),
            ("topic", "topic", codeableconcept.CodeableConcept, True, None, False),
            ("trigger", "trigger", triggerdefinition.TriggerDefinition, True, None, False),
            ("url", "url", str, False, None, False),
            ("usage", "usage", str, False, None, False),
            ("useContext", "useContext", usagecontext.UsageContext, True, None, False),
            ("version", "version", str, False, None, False),
        ])
        return js


from . import codeableconcept
from . import contactdetail
from . import contributor
from . import datarequirement
from . import fhirdate
from . import identifier
from . import parameterdefinition
from . import period
from . import relatedartifact
from . import triggerdefinition
from . import usagecontext
