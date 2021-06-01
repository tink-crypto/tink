# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.testing.cross_language.util._primitives."""

import datetime
from absl.testing import absltest

from proto.testing import testing_api_pb2
from tink import jwt
from util import _primitives


class PrimitivesTest(absltest.TestCase):

  def test_split_merge_timestamp(self):
    dt = datetime.datetime.fromtimestamp(1234.5678, datetime.timezone.utc)
    seconds, nanos = _primitives.split_datetime(dt)
    self.assertEqual(seconds, 1234)
    self.assertEqual(nanos, 567800000)
    self.assertEqual(_primitives.to_datetime(seconds, nanos), dt)

  def test_raw_jwt_to_proto_to_verified_jwt(self):
    nbf = datetime.datetime.fromtimestamp(1234567.89, datetime.timezone.utc)
    iat = datetime.datetime.fromtimestamp(2345678.9, datetime.timezone.utc)
    exp = datetime.datetime.fromtimestamp(3456789, datetime.timezone.utc)
    raw = jwt.new_raw_jwt(
        issuer='issuer',
        subject='subject',
        audiences=['audience1', 'audience2'],
        jwt_id='jwt_id',
        not_before=nbf,
        issued_at=iat,
        expiration=exp,
        custom_claims={
            'null': None,
            'string': 'aString',
            'number': 123.456,
            'integer': 123,
            'bool': True,
            'list': [None, True, 'foo', 42, {'pi': 3.14}],
            'obj': {'list': [1, 3.14], 'null': None, 'bool': False}
        })
    proto = _primitives.raw_jwt_to_proto(raw)
    verified = _primitives.proto_to_verified_jwt(proto)
    self.assertEqual(verified.issuer(), 'issuer')
    self.assertEqual(verified.subject(), 'subject')
    self.assertEqual(verified.audiences(), ['audience1', 'audience2'])
    self.assertEqual(verified.jwt_id(), 'jwt_id')
    self.assertEqual(verified.not_before(), nbf)
    self.assertEqual(verified.issued_at(), iat)
    self.assertEqual(verified.expiration(), exp)
    self.assertEqual(
        verified.custom_claim_names(),
        {'null', 'string', 'number', 'integer', 'bool', 'list', 'obj'})
    self.assertIsNone(verified.custom_claim('null'))
    self.assertEqual(verified.custom_claim('string'), 'aString')
    self.assertEqual(verified.custom_claim('number'), 123.456)
    self.assertEqual(verified.custom_claim('integer'), 123)
    self.assertEqual(verified.custom_claim('bool'), True)
    self.assertEqual(verified.custom_claim('list'),
                     [None, True, 'foo', 42, {'pi': 3.14}])
    self.assertEqual(
        verified.custom_claim('obj'),
        {'list': [1, 3.14], 'null': None, 'bool': False})

  def test_empty_raw_jwt_to_proto_to_verified_jwt(self):
    raw = jwt.new_raw_jwt()
    proto = _primitives.raw_jwt_to_proto(raw)
    verified = _primitives.proto_to_verified_jwt(proto)
    self.assertFalse(verified.has_issuer())
    self.assertFalse(verified.has_subject())
    self.assertFalse(verified.has_audiences())
    self.assertFalse(verified.has_jwt_id())
    self.assertFalse(verified.has_not_before())
    self.assertFalse(verified.has_issued_at())
    self.assertFalse(verified.has_expiration())
    self.assertEmpty(verified.custom_claim_names())

  def test_jwt_validator_to_proto(self):
    now = datetime.datetime.fromtimestamp(1234567.125, datetime.timezone.utc)
    validator = jwt.new_validator(
        expected_issuer='issuer',
        expected_subject='subject',
        expected_audience='audience',
        clock_skew=datetime.timedelta(seconds=123),
        fixed_now=now)
    proto = _primitives.jwt_validator_to_proto(validator)
    expected = testing_api_pb2.JwtValidator()
    expected.issuer.value = 'issuer'
    expected.subject.value = 'subject'
    expected.audience.value = 'audience'
    expected.clock_skew.seconds = 123
    expected.now.seconds = 1234567
    expected.now.nanos = 125000000
    self.assertEqual(proto, expected)

  def test_empty_jwt_validator_to_proto(self):
    validator = jwt.new_validator()
    proto = _primitives.jwt_validator_to_proto(validator)
    expected = testing_api_pb2.JwtValidator()
    expected.clock_skew.seconds = 0
    self.assertEqual(proto, expected)

if __name__ == '__main__':
  absltest.main()
