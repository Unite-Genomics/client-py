#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Generated from FHIR 1.7.0.10061 on 2016-10-24.
#  2016, SMART Health IT.


import os
import io
import unittest
import json
from . import codesystem
from .fhirdate import FHIRDate


class CodeSystemTests(unittest.TestCase):
    def instantiate_from(self, filename):
        datadir = os.environ.get('FHIR_UNITTEST_DATADIR') or ''
        with io.open(os.path.join(datadir, filename), 'r', encoding='utf-8') as handle:
            js = json.load(handle)
            self.assertEqual("CodeSystem", js["resourceType"])
        return codesystem.CodeSystem(js)
    
    def testCodeSystem1(self):
        inst = self.instantiate_from("codesystem-example.json")
        self.assertIsNotNone(inst, "Must have instantiated a CodeSystem instance")
        self.implCodeSystem1(inst)
        
        js = inst.as_json()
        self.assertEqual("CodeSystem", js["resourceType"])
        inst2 = codesystem.CodeSystem(js)
        self.implCodeSystem1(inst2)
    
    def implCodeSystem1(self, inst):
        self.assertTrue(inst.caseSensitive)
        self.assertEqual(inst.concept[0].code, "chol-mmol")
        self.assertEqual(inst.concept[0].definition, "Serum Cholesterol, in mmol/L")
        self.assertEqual(inst.concept[0].designation[0].use.code, "internal-label")
        self.assertEqual(inst.concept[0].designation[0].use.system, "http://acme.com/config/fhir/codesystems/internal")
        self.assertEqual(inst.concept[0].designation[0].value, "From ACME POC Testing")
        self.assertEqual(inst.concept[0].display, "SChol (mmol/L)")
        self.assertEqual(inst.concept[1].code, "chol-mass")
        self.assertEqual(inst.concept[1].definition, "Serum Cholesterol, in mg/L")
        self.assertEqual(inst.concept[1].designation[0].use.code, "internal-label")
        self.assertEqual(inst.concept[1].designation[0].use.system, "http://acme.com/config/fhir/codesystems/internal")
        self.assertEqual(inst.concept[1].designation[0].value, "From Paragon Labs")
        self.assertEqual(inst.concept[1].display, "SChol (mg/L)")
        self.assertEqual(inst.concept[2].code, "chol")
        self.assertEqual(inst.concept[2].definition, "Serum Cholesterol")
        self.assertEqual(inst.concept[2].designation[0].use.code, "internal-label")
        self.assertEqual(inst.concept[2].designation[0].use.system, "http://acme.com/config/fhir/codesystems/internal")
        self.assertEqual(inst.concept[2].designation[0].value, "Obdurate Labs uses this with both kinds of units...")
        self.assertEqual(inst.concept[2].display, "SChol")
        self.assertEqual(inst.contact[0].name, "FHIR project team")
        self.assertEqual(inst.contact[0].telecom[0].system, "other")
        self.assertEqual(inst.contact[0].telecom[0].value, "http://hl7.org/fhir")
        self.assertEqual(inst.content, "complete")
        self.assertEqual(inst.date.date, FHIRDate("2016-01-28").date)
        self.assertEqual(inst.date.as_json(), "2016-01-28")
        self.assertEqual(inst.description, "This is an example code system that includes all the ACME codes for serum/plasma cholesterol from v2.36.")
        self.assertTrue(inst.experimental)
        self.assertEqual(inst.id, "example")
        self.assertEqual(inst.identifier.system, "http://acme.com/identifiers/codesystems")
        self.assertEqual(inst.identifier.value, "internal-cholesterol-inl")
        self.assertEqual(inst.meta.profile[0], "http://hl7.org/fhir/StructureDefinition/codesystem-shareable-definition")
        self.assertEqual(inst.name, "ACME Codes for Cholesterol in Serum/Plasma")
        self.assertEqual(inst.publisher, "HL7 International")
        self.assertEqual(inst.status, "draft")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.url, "http://hl7.org/fhir/CodeSystem/example")
        self.assertEqual(inst.version, "20160128")
    
    def testCodeSystem2(self):
        inst = self.instantiate_from("codesystem-list-example-codes.json")
        self.assertIsNotNone(inst, "Must have instantiated a CodeSystem instance")
        self.implCodeSystem2(inst)
        
        js = inst.as_json()
        self.assertEqual("CodeSystem", js["resourceType"])
        inst2 = codesystem.CodeSystem(js)
        self.implCodeSystem2(inst2)
    
    def implCodeSystem2(self, inst):
        self.assertTrue(inst.caseSensitive)
        self.assertEqual(inst.concept[0].code, "alerts")
        self.assertEqual(inst.concept[0].definition, "A list of alerts for the patient.")
        self.assertEqual(inst.concept[0].display, "Alerts")
        self.assertEqual(inst.concept[1].code, "adverserxns")
        self.assertEqual(inst.concept[1].definition, "A list of part adverse reactions.")
        self.assertEqual(inst.concept[1].display, "Adverse Reactions")
        self.assertEqual(inst.concept[2].code, "allergies")
        self.assertEqual(inst.concept[2].definition, "A list of Allergies for the patient.")
        self.assertEqual(inst.concept[2].display, "Allergies")
        self.assertEqual(inst.concept[3].code, "medications")
        self.assertEqual(inst.concept[3].definition, "A list of medication statements for the patient.")
        self.assertEqual(inst.concept[3].display, "Medication List")
        self.assertEqual(inst.concept[4].code, "problems")
        self.assertEqual(inst.concept[4].definition, "A list of problems that the patient is known of have (or have had in the past).")
        self.assertEqual(inst.concept[4].display, "Problem List")
        self.assertEqual(inst.concept[5].code, "worklist")
        self.assertEqual(inst.concept[5].definition, "A list of items that constitute a set of work to be performed (typically this code would be specialized for more specific uses, such as a ward round list).")
        self.assertEqual(inst.concept[5].display, "Worklist")
        self.assertEqual(inst.concept[6].code, "waiting")
        self.assertEqual(inst.concept[6].definition, "A list of items waiting for an event (perhaps a surgical patient waiting list).")
        self.assertEqual(inst.concept[6].display, "Waiting List")
        self.assertEqual(inst.concept[7].code, "protocols")
        self.assertEqual(inst.concept[7].definition, "A set of protocols to be followed.")
        self.assertEqual(inst.concept[7].display, "Protocols")
        self.assertEqual(inst.concept[8].code, "plans")
        self.assertEqual(inst.concept[8].definition, "A set of care plans that apply in a particular context of care.")
        self.assertEqual(inst.concept[8].display, "Care Plans")
        self.assertEqual(inst.contact[0].telecom[0].system, "other")
        self.assertEqual(inst.contact[0].telecom[0].value, "http://hl7.org/fhir")
        self.assertEqual(inst.content, "complete")
        self.assertEqual(inst.description, "Example use codes for the List resource - typical kinds of use.")
        self.assertTrue(inst.experimental)
        self.assertEqual(inst.id, "list-example-codes")
        self.assertEqual(inst.identifier.system, "urn:ietf:rfc:3986")
        self.assertEqual(inst.identifier.value, "urn:oid:2.16.840.1.113883.4.642.1.173")
        self.assertEqual(inst.meta.lastUpdated.date, FHIRDate("2016-10-23T09:34:26.019+00:00").date)
        self.assertEqual(inst.meta.lastUpdated.as_json(), "2016-10-23T09:34:26.019+00:00")
        self.assertEqual(inst.meta.profile[0], "http://hl7.org/fhir/StructureDefinition/codesystem-shareable-definition")
        self.assertEqual(inst.name, "Example Use Codes for List")
        self.assertEqual(inst.publisher, "FHIR Project")
        self.assertEqual(inst.status, "draft")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.url, "http://hl7.org/fhir/list-example-use-codes")
        self.assertEqual(inst.valueSet, "http://hl7.org/fhir/ValueSet/list-example-codes")
        self.assertEqual(inst.version, "1.7.0")

