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
"""Tests for tink.python.tink.jwt._verified_jwt."""


import datetime

from absl.testing import absltest
from tink import jwt

ISSUED_AT = datetime.datetime.fromtimestamp(1582230020, datetime.timezone.utc)
NOT_BEFORE = datetime.datetime.fromtimestamp(1893553445, datetime.timezone.utc)
EXPIRATION = datetime.datetime.fromtimestamp(2218027244, datetime.timezone.utc)


class VerifiedJwtTest(absltest.TestCase):

  def test_empty(self):
    token = jwt.VerifiedJwt._create(jwt.new_raw_jwt(without_expiration=True))
    with self.assertRaises(KeyError):
      token.type_header()
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
    self.assertFalse(token.has_issuer())
    self.assertFalse(token.has_subject())
    self.assertFalse(token.has_jwt_id())
    self.assertFalse(token.has_audiences())
    self.assertFalse(token.has_expiration())
    self.assertFalse(token.has_issued_at())
    self.assertFalse(token.has_not_before())

  def test_full(self):
    token = jwt.VerifiedJwt._create(
        jwt.new_raw_jwt(
            type_header='TypeHeader',
            issuer='Issuer',
            subject='Subject',
            jwt_id='JWT ID',
            audiences=['bob', 'eve'],
            expiration=EXPIRATION,
            issued_at=ISSUED_AT,
            not_before=NOT_BEFORE))
    self.assertTrue(token.has_type_header())
    self.assertEqual(token.type_header(), 'TypeHeader')
    self.assertTrue(token.has_issuer())
    self.assertEqual(token.issuer(), 'Issuer')
    self.assertTrue(token.has_subject())
    self.assertEqual(token.subject(), 'Subject')
    self.assertTrue(token.has_jwt_id())
    self.assertEqual(token.jwt_id(), 'JWT ID')
    self.assertTrue(token.has_audiences())
    self.assertEqual(token.audiences(), ['bob', 'eve'])
    self.assertTrue(token.has_expiration())
    self.assertEqual(token.expiration(), EXPIRATION)
    self.assertTrue(token.has_issued_at())
    self.assertEqual(token.issued_at(), ISSUED_AT)
    self.assertTrue(token.has_not_before())
    self.assertEqual(token.not_before(), NOT_BEFORE)

  def test_custom_claims(self):
    custom_claims = {'string': 'value',
                     'boolean': True,
                     'number': 123.456,
                     'integer': 123,
                     'null': None,
                     'array': [1, None, 'Bob', 2.2, {'foo': 'bar'}],
                     'object': {'one': {'two': 3}}}
    token = token = jwt.VerifiedJwt._create(
        jwt.new_raw_jwt(custom_claims=custom_claims, without_expiration=True))
    self.assertCountEqual(
        token.custom_claim_names(),
        {'string', 'boolean', 'number', 'integer', 'null', 'array', 'object'})
    self.assertEqual(token.custom_claim('string'), 'value')
    self.assertEqual(token.custom_claim('boolean'), True)
    self.assertEqual(token.custom_claim('number'), 123.456)
    self.assertEqual(token.custom_claim('integer'), 123)
    self.assertIsNone(token.custom_claim('null'))
    self.assertEqual(
        token.custom_claim('array'),
        [1, None, 'Bob', 2.2, {'foo': 'bar'}])
    self.assertEqual(token.custom_claim('object'), {'one': {'two': 3}})


if __name__ == '__main__':
  absltest.main()
