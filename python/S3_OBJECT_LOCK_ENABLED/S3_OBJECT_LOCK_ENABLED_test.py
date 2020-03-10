# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import unittest
from mock import patch, MagicMock

from rdklib import Evaluation, ComplianceType
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::S3::Bucket'

#############
# Main Code #
#############

MODULE = __import__('S3_OBJECT_LOCK_ENABLED')
RULE = MODULE.S3_OBJECT_LOCK_ENABLED()

CLIENT_FACTORY = MagicMock()

#example for mocking S3 API calls
S3_CLIENT_MOCK = MagicMock()
CONFIG_CLIENT_MOCK = MagicMock()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 's3':
        return S3_CLIENT_MOCK
    if client_name == 'config':
        return CONFIG_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    def test_no_s3_buckets(self):
        rule_parameters = {"Mode":"GOVERNANCE"}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config.return_value = {"Results":[]}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.NOT_APPLICABLE)
        ]
        rdklibtest.assert_successful_evaluation(self, response[0], resp_expected, 1)

    def test_compliance_s3_Mode(self):
        rule_parameters = {"Mode":"GOVERNANCE"}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE'}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "test-s3", "AWS::S3::Bucket")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_compliance_s3_ModeDays(self):
        rule_parameters = {"Mode":"GOVERNANCE", "Days":100}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Days': 100}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "test-s3", "AWS::S3::Bucket")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
    
    def test_compliance_s3_ModeYears(self):
        rule_parameters = {"Mode":"GOVERNANCE", "Years":1}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Years': 10}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "test-s3", "AWS::S3::Bucket")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
    
    def test_compliance_s3_ModeDaysYears(self):
        rule_parameters = {"Mode":"GOVERNANCE", "Days":100, "Years":9}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Years': 10}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "test-s3", "AWS::S3::Bucket")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_noncompliance_s3_Mode(self):
        rule_parameters = {"Mode":"GOVERNANCE"}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE'}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, "test-s3", "AWS::S3::Bucket","ObjectLockConfiguration doesn't match.")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
    
    def test_noncompliance_s3_ModeDays(self):
        rule_parameters = {"Mode":"GOVERNANCE", "Days":100}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Days': 50}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, "test-s3", "AWS::S3::Bucket", "ObjectLockConfiguration doesn't match.")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
    
    def test_noncompliance_s3_ModeYears(self):
        rule_parameters = {"Mode":"GOVERNANCE", "Years":2}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Years': 1}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, "test-s3", "AWS::S3::Bucket", "ObjectLockConfiguration doesn't match.")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_noncompliance_s3_ModeDaysYears(self):
        rule_parameters = {"Mode":"GOVERNANCE", "Days":100, "Years":9}
        rule_parameters = RULE.evaluate_parameters(rule_parameters)
        CONFIG_CLIENT_MOCK.select_resource_config = MagicMock(return_value={"Results":['{"resourceName":"test-s3"}']})
        S3_CLIENT_MOCK.get_object_lock_configuration.return_value = {'ResponseMetadata': {'RequestId': 'E411AAFF0E0210C1'}, 'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Years': 9}}}}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, rule_parameters)
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, "test-s3", "AWS::S3::Bucket", "ObjectLockConfiguration doesn't match.")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
