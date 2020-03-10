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
'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  S3_OBJECT_LOCK_ENABLED

Description:
  Check whether S3 Buckets are Object Lock enabled. There should be a retention mode and retention period to be applied to the bucket lock.

Rationale:
  Object Lock enabled on all S3 buckets to block object version deletion.

Indicative Severity:
  Medium

Trigger:
  Periodic

Reports on:
  AWS::S3::Bucket

Rule Parameters:
  Mode
    The default Object Lock retention mode you want to apply to new objects placed in the specified bucket.
  Days
    The number of days that you want to specify for the default retention period.
  Years
    The number of years that you want to specify for the default retention period.

Scenarios:
  Scenario: 1
    Given: No S3 buckets available for the account
     Then: Return NOT_APPLICABLE
  Scenario: 2
    Given: S3 bucket is not object lock enabled
     Then: Return NON_COMPLIANT
  Scenario: 3
    Given: S3 bucket is object lock enabled with mode
     Then: Return COMPLIANT
  Scenario: 4
    Given: S3 bucket is object lock enabled with mode and days (actual bucket days should be greater than the parameter days)
     Then: Return COMPLIANT
  Scenario: 5
    Given: S3 bucket is object lock enabled with mode and years (actual bucket years should be greater than the parameter years)
     Then: Return COMPLIANT
  Scenario: 6
    Given: S3 bucket is object lock enabled with mode, days and yeaas (actual bucket days(days + (years*365)) should be greater than the parameter days + (years*365))
     Then: Return COMPLIANT
  Scenario: 7
    Given: S3 bucket is object lock enabled with different mode
     Then: Return NON_COMPLIANT
  Scenario: 8
    Given: S3 bucket is object lock enabled with mode and days (actual bucket days are less than the parameter days)
     Then: Return NON_COMPLIANT
  Scenario: 9
    Given: S3 bucket is object lock enabled with mode and years (actual bucket years are less than the parameter years)
     Then: Return NON_COMPLIANT
  Scenario: 10
    Given: S3 bucket is object lock enabled with mode, days and yeaas (actual bucket days(days + (years*365)) are less than the parameter days + (years*365))
     Then: Return NON_COMPLIANT
'''

import json

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError

RESOURCE_TYPE = 'AWS::S3::Bucket'

class S3_OBJECT_LOCK_ENABLED(ConfigRule):

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        s3_client = client_factory.build_client("s3") # AWS S3 Client
        config_client = client_factory.build_client('config') # AWS Config Service Client
        evaluations = []
        print('valid_rule_parameters',valid_rule_parameters)
        valid_rule_parameters = self.evaluate_parameters(valid_rule_parameters)
        for s3_bucket_name in get_buckets(config_client):

            isexception = False
            try:
                response = s3_client.get_object_lock_configuration(Bucket=s3_bucket_name)
            except:
                isexception = True
            if isexception or 'ObjectLockConfiguration' not in response:
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, s3_bucket_name, RESOURCE_TYPE, "No ObjectLockConfiguration exist for this bucket."))
            else:
                days = 0
                years = 0
                mode = None
                #If 'Rule' exists in the response, then only derive 'mode'
                if response.get('ObjectLockConfiguration').get('Rule', 0) != 0 :
                    mode = response['ObjectLockConfiguration']['Rule']['DefaultRetention'].get('Mode',None)

                #If 'Days' exists in the response, then only derive 'Days' otherwise make it 0
                if response.get('ObjectLockConfiguration').get('Rule').get('DefaultRetention').get('Days',0) > 0:
                    days = response['ObjectLockConfiguration']['Rule']['DefaultRetention']['Days']

                #If 'Years' exists in the response, then only derive 'Years' otherwise make it 0
                if response.get('ObjectLockConfiguration').get('Rule').get('DefaultRetention').get('Years',0) > 0:
                    years = response['ObjectLockConfiguration']['Rule']['DefaultRetention']['Years']

                days_in_param = valid_rule_parameters.get('Days',0)
                years_in_param = valid_rule_parameters.get('Years',0)
                #Calculate days from years
                days_in_param = (years_in_param * 365) + days_in_param
                totaldays = (years * 365) + days

                if mode == valid_rule_parameters.get('Mode') and totaldays >= days_in_param:
                    evaluations.append(Evaluation(ComplianceType.COMPLIANT, s3_bucket_name, RESOURCE_TYPE))
                else:
                    evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, s3_bucket_name, RESOURCE_TYPE, "ObjectLockConfiguration doesn't match."))

        #If not buckets available, then NOT_APPLICABLE
        if not evaluations:
            evaluations.append([Evaluation(ComplianceType.NOT_APPLICABLE)])
        return evaluations

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = rule_parameters
        if 'Mode' not in rule_parameters:
            raise InvalidParametersError('The Config Rule must have the parameter "Mode" with values either "GOVERNANCE" or "COMPLIANCE"')
        #if 'Days' not in rule_parameters and 'Years' not in rule_parameters:
        #    raise InvalidParametersError('The Config Rule must have either "Days" or "Years" ')
        
        # The int() function will raise an error if the string configured can't be converted to an integer
        if 'Days' in rule_parameters:
            try:
                rule_parameters['Days'] = int(rule_parameters['Days'])
            except ValueError:
                raise InvalidParametersError('The parameter "Days" must be a integer')

            if rule_parameters['Days'] < 1:
                raise InvalidParametersError('The parameter "Days" must be greater than 0')

        # The int() function will raise an error if the string configured can't be converted to an integer
        if 'Years' in rule_parameters:
            try:
                rule_parameters['Years'] = int(rule_parameters['Years'])
            except ValueError:
                raise InvalidParametersError('The parameter "Years" must be a integer')

            if rule_parameters['Years'] < 1:
                raise InvalidParametersError('The parameter "Years" must be greater than 0')
        
        return valid_rule_parameters

#Get all the bucket names using AWSConfig advanced query and pagination
def get_buckets(config_client):
    sql = "select * where resourceType = 'AWS::S3::Bucket'"
    next_token = True
    response = config_client.select_resource_config(Expression=sql, Limit=5)
    while next_token:
        for result in response['Results']:
            yield json.loads(result)['resourceName']
        if 'NextToken' in response:
            next_token = response['NextToken']
            response = config_client.select_resource_config(Expression=sql, NextToken=next_token, Limit=5)
        else:
            next_token = False


def lambda_handler(event, context):
    my_rule = S3_OBJECT_LOCK_ENABLED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
