#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Generated from FHIR 1.7.0.10061 on 2016-10-24.
#  2016, SMART Health IT.


import os
import io
import unittest
import json
from . import coverage
from .fhirdate import FHIRDate


class CoverageTests(unittest.TestCase):
    def instantiate_from(self, filename):
        datadir = os.environ.get('FHIR_UNITTEST_DATADIR') or ''
        with io.open(os.path.join(datadir, filename), 'r', encoding='utf-8') as handle:
            js = json.load(handle)
            self.assertEqual("Coverage", js["resourceType"])
        return coverage.Coverage(js)
    
    def testCoverage1(self):
        inst = self.instantiate_from("coverage-example-2.json")
        self.assertIsNotNone(inst, "Must have instantiated a Coverage instance")
        self.implCoverage1(inst)
        
        js = inst.as_json()
        self.assertEqual("Coverage", js["resourceType"])
        inst2 = coverage.Coverage(js)
        self.implCoverage1(inst2)
    
    def implCoverage1(self, inst):
        self.assertEqual(inst.dependent, 1)
        self.assertEqual(inst.id, "7546D")
        self.assertEqual(inst.identifier[0].system, "http://xyz.com/codes/identifier")
        self.assertEqual(inst.identifier[0].value, "AB9876")
        self.assertEqual(inst.level[0].code, "WESTAIR")
        self.assertEqual(inst.level[0].display, "Western Airlines")
        self.assertEqual(inst.level[0].system, "http://xyz.com/codes/group")
        self.assertEqual(inst.level[1].code, "11024")
        self.assertEqual(inst.level[1].display, "Aircraft Maintenance Division")
        self.assertEqual(inst.level[1].system, "http://xyz.com/codes/plan")
        self.assertEqual(inst.level[2].code, "D15C9")
        self.assertEqual(inst.level[2].display, "Platinum")
        self.assertEqual(inst.level[2].system, "http://xyz.com/codes/subplan")
        self.assertEqual(inst.period.end.date, FHIRDate("2012-03-17").date)
        self.assertEqual(inst.period.end.as_json(), "2012-03-17")
        self.assertEqual(inst.period.start.date, FHIRDate("2011-03-17").date)
        self.assertEqual(inst.period.start.as_json(), "2011-03-17")
        self.assertEqual(inst.relationship.code, "self")
        self.assertEqual(inst.status, "active")
        self.assertEqual(inst.text.div, "<div xmlns=\"http://www.w3.org/1999/xhtml\">A human-readable rendering of the coverage</div>")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type.code, "EHCPOL")
        self.assertEqual(inst.type.display, "extended healthcare")
        self.assertEqual(inst.type.system, "http://hl7.org/fhir/v3/ActCode")
    
    def testCoverage2(self):
        inst = self.instantiate_from("coverage-example-ehic.json")
        self.assertIsNotNone(inst, "Must have instantiated a Coverage instance")
        self.implCoverage2(inst)
        
        js = inst.as_json()
        self.assertEqual("Coverage", js["resourceType"])
        inst2 = coverage.Coverage(js)
        self.implCoverage2(inst2)
    
    def implCoverage2(self, inst):
        self.assertEqual(inst.id, "7547E")
        self.assertEqual(inst.identifier[0].system, "http://ehic.com/insurer/123456789/member")
        self.assertEqual(inst.identifier[0].value, "A123456780")
        self.assertEqual(inst.period.end.date, FHIRDate("2012-03-17").date)
        self.assertEqual(inst.period.end.as_json(), "2012-03-17")
        self.assertEqual(inst.relationship.code, "self")
        self.assertEqual(inst.status, "active")
        self.assertEqual(inst.text.div, "<div xmlns=\"http://www.w3.org/1999/xhtml\">A human-readable rendering of the European Health Insurance Card</div>")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type.code, "EHCPOL")
        self.assertEqual(inst.type.display, "extended healthcare")
        self.assertEqual(inst.type.system, "http://hl7.org/fhir/v3/ActCode")
    
    def testCoverage3(self):
        inst = self.instantiate_from("coverage-example.json")
        self.assertIsNotNone(inst, "Must have instantiated a Coverage instance")
        self.implCoverage3(inst)
        
        js = inst.as_json()
        self.assertEqual("Coverage", js["resourceType"])
        inst2 = coverage.Coverage(js)
        self.implCoverage3(inst2)
    
    def implCoverage3(self, inst):
        self.assertEqual(inst.dependent, 1)
        self.assertEqual(inst.id, "9876B1")
        self.assertEqual(inst.identifier[0].system, "http://benefitsinc.com/certificate")
        self.assertEqual(inst.identifier[0].value, "12345")
        self.assertEqual(inst.level[0].code, "CBI35")
        self.assertEqual(inst.level[0].display, "Corporate Baker's Inc. Plan#35")
        self.assertEqual(inst.level[0].system, "http://benefitsinc.com/plan")
        self.assertEqual(inst.level[1].code, "123")
        self.assertEqual(inst.level[1].display, "Trainee Part-time Benefits")
        self.assertEqual(inst.level[1].system, "http://benefitsinc.com/subplan")
        self.assertEqual(inst.period.end.date, FHIRDate("2012-05-23").date)
        self.assertEqual(inst.period.end.as_json(), "2012-05-23")
        self.assertEqual(inst.period.start.date, FHIRDate("2011-05-23").date)
        self.assertEqual(inst.period.start.as_json(), "2011-05-23")
        self.assertEqual(inst.relationship.code, "self")
        self.assertEqual(inst.sequence, 1)
        self.assertEqual(inst.status, "active")
        self.assertEqual(inst.text.div, "<div xmlns=\"http://www.w3.org/1999/xhtml\">A human-readable rendering of the coverage</div>")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type.code, "EHCPOL")
        self.assertEqual(inst.type.display, "extended healthcare")
        self.assertEqual(inst.type.system, "http://hl7.org/fhir/v3/ActCode")

