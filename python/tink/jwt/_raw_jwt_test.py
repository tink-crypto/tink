# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
"""Tests for tink.python.tink.jwt._raw_jwt."""

import datetime
import json

from typing import cast, Dict, List, Text

from absl.testing import absltest
# from absl.testing import parameterized

from tink import jwt

ISSUED_AT_TIMESTAMP = 1582230020
ISSUED_AT = datetime.datetime.fromtimestamp(ISSUED_AT_TIMESTAMP,
                                            datetime.timezone.utc)

NOT_BEFORE_TIMESTAMP = 1893553445
NOT_BEFORE = datetime.datetime.fromtimestamp(NOT_BEFORE_TIMESTAMP,
                                             datetime.timezone.utc)

EXPIRATION_TIMESTAMP = 2218027244
EXPIRATION = datetime.datetime.fromtimestamp(EXPIRATION_TIMESTAMP,
                                             datetime.timezone.utc)


class RawJwtTest(absltest.TestCase):

  def test_datetime(self):
    t = 1893553445
    d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    self.assertEqual(int(d.timestamp()), t)

  def test_empty_access_raises_error(self):
    token = jwt.new_raw_jwt()
    with self.assertRaises(KeyError):
      token.issuer()
    with self.assertRaises(KeyError):
      token.subject()
    with self.assertRaises(KeyError):
      token.jwt_id()
    with self.assertRaises(KeyError):
      token.audiences()
    with self.assertRaises(KeyError):
      token.expiration()
    with self.assertRaises(KeyError):
      token.issued_at()
    with self.assertRaises(KeyError):
      token.not_before()
    with self.assertRaises(KeyError):
      token.custom_claim('unknown')

  def test_empty_has_returns_false(self):
    token = jwt.new_raw_jwt()
    self.assertFalse(token.has_issuer())
    self.assertFalse(token.has_subject())
    self.assertFalse(token.has_jwt_id())
    self.assertFalse(token.has_audiences())
    self.assertFalse(token.has_expiration())
    self.assertFalse(token.has_issued_at())
    self.assertFalse(token.has_not_before())

  def test_issuer(self):
    token = jwt.new_raw_jwt(issuer='Issuer')
    self.assertTrue(token.has_issuer())
    self.assertEqual(token.issuer(), 'Issuer')

  def test_subject(self):
    token = jwt.new_raw_jwt(subject='Subject')
    self.assertTrue(token.has_subject())
    self.assertEqual(token.subject(), 'Subject')

  def test_jwt_id(self):
    token = jwt.new_raw_jwt(jwt_id='JWT ID')
    self.assertTrue(token.has_jwt_id())
    self.assertEqual(token.jwt_id(), 'JWT ID')

  def test_audiences(self):
    token = jwt.new_raw_jwt(audiences=['bob', 'eve'])
    self.assertTrue(token.has_audiences())
    self.assertEqual(token.audiences(), ['bob', 'eve'])

  def test_string_audiences(self):
    token = jwt.new_raw_jwt(audiences=cast(List[Text], 'bob'))
    self.assertTrue(token.has_audiences())
    self.assertEqual(token.audiences(), ['bob'])

  def test_empty_audiences(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.new_raw_jwt(audiences=[])

  def test_expiration(self):
    token = jwt.new_raw_jwt(expiration=EXPIRATION)
    self.assertTrue(token.has_expiration())
    self.assertEqual(token.expiration(), EXPIRATION)

  def test_issued_at(self):
    token = jwt.new_raw_jwt(issued_at=ISSUED_AT)
    self.assertTrue(token.has_issued_at())
    self.assertEqual(token.issued_at(), ISSUED_AT)

  def test_not_before(self):
    token = jwt.new_raw_jwt(not_before=NOT_BEFORE)
    self.assertTrue(token.has_not_before())
    self.assertEqual(token.not_before(), NOT_BEFORE)

  def test_rejects_naive_time(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.new_raw_jwt(issued_at=ISSUED_AT.replace(tzinfo=None))
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.new_raw_jwt(not_before=NOT_BEFORE.replace(tzinfo=None))
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.new_raw_jwt(expiration=EXPIRATION.replace(tzinfo=None))

  def test_custom_claims(self):
    custom_claims = {'string': 'value',
                     'boolean': True,
                     'number': 123.456,
                     'integer': 123,
                     'null': None,
                     'array': [1, None, 'Bob', 2.2, {'foo': 'bar'}],
                     'object': {'one': {'two': 3}}}
    token = jwt.new_raw_jwt(custom_claims=custom_claims)
    self.assertCountEqual(
        token.custom_claim_names(),
        {'string', 'boolean', 'number', 'integer', 'null', 'array', 'object'})
    self.assertEqual(token.custom_claim('string'), 'value')
    self.assertEqual(token.custom_claim('boolean'), True)
    self.assertEqual(token.custom_claim('number'), 123.456)
    self.assertEqual(token.custom_claim('integer'), 123)
    self.assertIsNone(token.custom_claim('null'))
    self.assertEqual(token.custom_claim('array'),
                     [1, None, 'Bob', 2.2, {'foo': 'bar'}])
    self.assertEqual(token.custom_claim('object'), {'one': {'two': 3}})

  def test_empty_custom_claim_names(self):
    token = jwt.new_raw_jwt()
    self.assertEmpty(token.custom_claim_names())

  def test_registered_name_as_custom_claim_is_invalid(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.new_raw_jwt(custom_claims={'iss': 'issuer'})

  def test_custom_claim_using_registered_name_fails(self):
    token = jwt.new_raw_jwt(issuer='issuer')
    with self.assertRaises(jwt.JwtInvalidError):
      token.custom_claim('iss')

  def test_null_custom_claim(self):
    token = jwt.new_raw_jwt(custom_claims={'null_claim': None})
    self.assertCountEqual(token.custom_claim_names(), ['null_claim'])
    self.assertIsNone(token.custom_claim('null_claim'))

  def test_payload(self):
    custom_claims = {'account_no': 1234,
                     'amount': 1.5,
                     'name': 'Peter',
                     'null': None,
                     'array': [1, None, 'Bob', 2.2, {'foo': 'bar'}],
                     'object': {'one': {'two': 3}}
                     }
    token = jwt.new_raw_jwt(
        issuer='Issuer',
        subject='Subject',
        audiences=['bob', 'eve'],
        jwt_id='JWT ID',
        issued_at=ISSUED_AT,
        not_before=NOT_BEFORE,
        expiration=EXPIRATION,
        custom_claims=custom_claims)
    self.assertEqual(
        json.loads(token.json_payload()), {
            'iss': 'Issuer',
            'sub': 'Subject',
            'jti': 'JWT ID',
            'aud': ['bob', 'eve'],
            'iat': ISSUED_AT_TIMESTAMP,
            'nbf': NOT_BEFORE_TIMESTAMP,
            'exp': EXPIRATION_TIMESTAMP,
            'account_no': 1234,
            'amount': 1.5,
            'name': 'Peter',
            'null': None,
            'array': [1, None, 'Bob', 2.2, {'foo': 'bar'}],
            'object': {'one': {'two': 3}}
        })

  def test_from_to_payload(self):
    payload = {
        'iss': 'Issuer',
        'sub': 'Subject',
        'jti': 'JWT ID',
        'aud': ['bob', 'eve'],
        'iat': ISSUED_AT_TIMESTAMP,
        'nbf': NOT_BEFORE_TIMESTAMP,
        'exp': EXPIRATION_TIMESTAMP,
        'account_no': 1234,
        'amount': 1.5,
        'name': 'Peter',
        'null': None,
        'array': [1, None, 'Bob', 2.2, {'foo': 'bar'}],
        'object': {'one': {'two': 3}}
    }
    token = jwt.raw_jwt_from_json_payload(json.dumps(payload))
    self.assertEqual(json.loads(token.json_payload()), payload)

  def test_from_to_payload_with_string_audience(self):
    payload = {
        'iss': 'Issuer',
        'aud': 'bob',
    }
    token = jwt.raw_jwt_from_json_payload(json.dumps(payload))
    expected = {
        'iss': 'Issuer',
        'aud': ['bob'],
    }
    self.assertEqual(json.loads(token.json_payload()), expected)

  def test_from_to_payload_with_wrong_issuer_fails(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.raw_jwt_from_json_payload('{"iss":123}')

  def test_from_to_payload_with_wrong_subject_fails(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.raw_jwt_from_json_payload('{"sub":123}')

  def test_from_to_payload_with_wrong_jwt_id_fails(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.raw_jwt_from_json_payload('{"jti":123}')

  def test_from_to_payload_with_wrong_expiration_fails(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.raw_jwt_from_json_payload('{"exp":"123"}')

  def test_from_to_payload_with_wrong_issued_at_fails(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.raw_jwt_from_json_payload('{"iat":"123"}')

  def test_from_to_payload_with_wrong_not_before_fails(self):
    with self.assertRaises(jwt.JwtInvalidError):
      jwt.raw_jwt_from_json_payload('{"nbf":"123"}')

  def test_modification(self):
    audiences = ['alice', 'bob']
    my_claim = {'one': 'two'}
    custom_claims = {'my_claim': my_claim}
    token = jwt.new_raw_jwt(
        issuer='Issuer',
        audiences=audiences,
        custom_claims=custom_claims)

    # modify inputs and outputs of token
    audiences.append('eve')
    custom_claims['new_claim'] = 456
    my_claim['three'] = 4
    output_claim = cast(Dict[Text, Text], token.custom_claim('my_claim'))
    output_claim['three'] = 4

    # modifications don't affect token.
    self.assertEqual(token.audiences(), ['alice', 'bob'])
    self.assertEqual(token.custom_claim_names(), {'my_claim'})
    self.assertEqual(token.custom_claim('my_claim'), {'one': 'two'})
    with self.assertRaises(KeyError):
      token.custom_claim('new_claim')


if __name__ == '__main__':
  absltest.main()
