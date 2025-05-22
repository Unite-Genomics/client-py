# These are settings for the FHIR class generator

from Python.settings import *

# classes/resources
write_resources = True
tpl_resource_target_ptrn = '../fhirclientdstu2/models/{}.py'     # where to write the generated class files to, with one placeholder for the class name
resource_base_target = '../fhirclientdstu2/models/'              # resource target directory, likely the same as `tpl_resource_target_ptrn` without the filename pattern

# factory methods
write_factory = True
tpl_factory_target = '../fhirclientdstu2/models/fhirelementfactory.py'

# unit tests
write_unittests = True
tpl_unittest_target_ptrn = '../fhirclientdstu2/models/{}_tests.py'
