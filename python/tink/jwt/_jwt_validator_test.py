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
"""Tests for tink.python.tink.jwt._jwt_validator."""

import datetime

from absl.testing import absltest
from tink import jwt
from tink.jwt import _jwt_validator


class JwtValidatorTest(absltest.TestCase):

  def test_validator_getters(self):
    fixed_now = datetime.datetime.fromtimestamp(12345, datetime.timezone.utc)
    clock_skew = datetime.timedelta(minutes=1)
    validator = jwt.new_validator(
        expected_type_header='type_header',
        expected_issuer='issuer',
        expected_subject='subject',
        expected_audience='audience',
        fixed_now=fixed_now,
        clock_skew=clock_skew)
    self.assertTrue(validator.has_expected_type_header())
    self.assertEqual(validator.expected_type_header(), 'type_header')
    self.assertTrue(validator.has_expected_issuer())
    self.assertEqual(validator.expected_issuer(), 'issuer')
    self.assertTrue(validator.has_expected_subject())
    self.assertEqual(validator.expected_subject(), 'subject')
    self.assertTrue(validator.has_expected_audience())
    self.assertEqual(validator.expected_audience(), 'audience')
    self.assertFalse(validator.allow_missing_expiration())
    self.assertFalse(validator.ignore_issuer())
    self.assertFalse(validator.ignore_subject())
    self.assertFalse(validator.ignore_audiences())
    self.assertTrue(validator.has_fixed_now())
    self.assertEqual(validator.fixed_now(), fixed_now)
    self.assertEqual(validator.clock_skew(), clock_skew)

  def test_validator_ignore_getters(self):
    validator = jwt.new_validator(
        allow_missing_expiration=True,
        ignore_type_header=True,
        ignore_issuer=True,
        ignore_subject=True,
        ignore_audiences=True)
    self.assertTrue(validator.allow_missing_expiration())
    self.assertTrue(validator.ignore_type_header())
    self.assertTrue(validator.ignore_issuer())
    self.assertTrue(validator.ignore_subject())
    self.assertTrue(validator.ignore_audiences())

  def test_empty_validator_getters(self):
    validator = jwt.new_validator()
    self.assertFalse(validator.has_expected_type_header())
    self.assertFalse(validator.has_expected_issuer())
    self.assertFalse(validator.has_expected_subject())
    self.assertFalse(validator.has_expected_audience())
    self.assertFalse(validator.has_fixed_now())
    self.assertFalse(validator.clock_skew(), datetime.timedelta())

  def test_too_much_clock_skew(self):
    with self.assertRaises(ValueError):
      jwt.new_validator(clock_skew=datetime.timedelta(minutes=20))

  def test_validate_expired_fails(self):
    expired = (datetime.datetime.now(tz=datetime.timezone.utc)
               - datetime.timedelta(minutes=1))
    token = jwt.new_raw_jwt(expiration=expired)
    validator = jwt.new_validator()
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_validate_not_expired_success(self):
    still_valid = (datetime.datetime.now(tz=datetime.timezone.utc)
                   + datetime.timedelta(minutes=1))
    token = jwt.new_raw_jwt(expiration=still_valid)
    validator = jwt.new_validator()
    _jwt_validator.validate(validator, token)

  def test_validate_token_that_expires_now_fails(self):
    now = datetime.datetime.fromtimestamp(1234.0, tz=datetime.timezone.utc)
    token = jwt.new_raw_jwt(expiration=now)
    validator = jwt.new_validator()
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_validate_recently_expired_with_clock_skew_success(self):
    recently_expired = (datetime.datetime.now(tz=datetime.timezone.utc)
                        - datetime.timedelta(minutes=1))
    token = jwt.new_raw_jwt(expiration=recently_expired)
    validator = jwt.new_validator(clock_skew=datetime.timedelta(minutes=2))
    # because of clock_skew, the recently expired token is valid
    _jwt_validator.validate(validator, token)

  def test_validate_not_before_in_the_future_fails(self):
    in_the_future = (datetime.datetime.now(tz=datetime.timezone.utc)
                     + datetime.timedelta(minutes=1))
    token = jwt.new_raw_jwt(not_before=in_the_future, without_expiration=True)
    validator = jwt.new_validator(allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_validate_not_before_in_the_past_success(self):
    in_the_past = (datetime.datetime.now(tz=datetime.timezone.utc)
                   - datetime.timedelta(minutes=1))
    token = jwt.new_raw_jwt(not_before=in_the_past, without_expiration=True)
    validator = jwt.new_validator(allow_missing_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_validate_not_before_is_now_success(self):
    now = datetime.datetime.fromtimestamp(12345, datetime.timezone.utc)
    token = jwt.new_raw_jwt(not_before=now, without_expiration=True)
    validator = jwt.new_validator(allow_missing_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_validate_not_before_almost_reached_with_clock_skew_success(self):
    in_one_minute = (datetime.datetime.now(tz=datetime.timezone.utc)
                     + datetime.timedelta(minutes=1))
    token = jwt.new_raw_jwt(not_before=in_one_minute, without_expiration=True)
    validator = jwt.new_validator(
        allow_missing_expiration=True, clock_skew=datetime.timedelta(minutes=2))
    _jwt_validator.validate(validator, token)

  def test_requires_type_header_but_no_type_header_set_fails(self):
    token = jwt.new_raw_jwt(without_expiration=True)
    validator = jwt.new_validator(
        expected_type_header='type_header', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_invalid_type_header_fails(self):
    token = jwt.new_raw_jwt(type_header='unknown', without_expiration=True)
    validator = jwt.new_validator(
        expected_type_header='type_header', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_correct_type_header_success(self):
    token = jwt.new_raw_jwt(type_header='type_header', without_expiration=True)
    validator = jwt.new_validator(
        expected_type_header='type_header', allow_missing_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_type_header_in_token_but_not_in_validator_fails(self):
    validator = jwt.new_validator(allow_missing_expiration=True)
    token_with_type_header = jwt.new_raw_jwt(
        type_header='type_header', without_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token_with_type_header)

  def test_ignore_type_header_success(self):
    validator = jwt.new_validator(
        ignore_type_header=True, allow_missing_expiration=True)
    token_without_type_header = jwt.new_raw_jwt(without_expiration=True)
    _jwt_validator.validate(validator, token_without_type_header)
    token_with_type_header = jwt.new_raw_jwt(
        type_header='type_header', without_expiration=True)
    _jwt_validator.validate(validator, token_with_type_header)

  def test_requires_issuer_but_no_issuer_set_fails(self):
    token = jwt.new_raw_jwt(without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_invalid_issuer_fails(self):
    token = jwt.new_raw_jwt(issuer='unknown', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_correct_issuer_success(self):
    token = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_issuer_in_token_but_not_in_validator_fails(self):
    validator = jwt.new_validator(allow_missing_expiration=True)
    token_with_issuer = jwt.new_raw_jwt(
        issuer='issuer', without_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token_with_issuer)

  def test_ignore_issuer_success(self):
    validator = jwt.new_validator(
        ignore_issuer=True, allow_missing_expiration=True)
    token_without_issuer = jwt.new_raw_jwt(without_expiration=True)
    _jwt_validator.validate(validator, token_without_issuer)
    token_with_issuer = jwt.new_raw_jwt(
        issuer='issuer', without_expiration=True)
    _jwt_validator.validate(validator, token_with_issuer)

  def test_requires_subject_but_no_subject_set_fails(self):
    token = jwt.new_raw_jwt(without_expiration=True)
    validator = jwt.new_validator(
        expected_subject='subject', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_invalid_subject_fails(self):
    token = jwt.new_raw_jwt(subject='unknown', without_expiration=True)
    validator = jwt.new_validator(
        expected_subject='subject', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_correct_subject_success(self):
    token = jwt.new_raw_jwt(subject='subject', without_expiration=True)
    validator = jwt.new_validator(
        expected_subject='subject', allow_missing_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_subject_in_token_but_not_in_validator_fails(self):
    validator = jwt.new_validator(allow_missing_expiration=True)
    token_with_subject = jwt.new_raw_jwt(
        subject='subject', without_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token_with_subject)

  def test_ignore_subject_success(self):
    validator = jwt.new_validator(
        ignore_subject=True, allow_missing_expiration=True)
    token_without_subject = jwt.new_raw_jwt(without_expiration=True)
    _jwt_validator.validate(validator, token_without_subject)
    token_with_subject = jwt.new_raw_jwt(
        subject='subject', without_expiration=True)
    _jwt_validator.validate(validator, token_with_subject)

  def test_requires_audience_but_no_audience_set_fails(self):
    token = jwt.new_raw_jwt(without_expiration=True)
    validator = jwt.new_validator(
        expected_audience='audience', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_wrong_audience_fails(self):
    token = jwt.new_raw_jwt(audiences=['unknown'], without_expiration=True)
    validator = jwt.new_validator(
        expected_audience='audience', allow_missing_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_correct_audience_success(self):
    token = jwt.new_raw_jwt(audiences=['you', 'me'], without_expiration=True)
    validator = jwt.new_validator(
        expected_audience='me', allow_missing_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_audience_in_token_but_not_in_validator_fails(self):
    validator = jwt.new_validator(allow_missing_expiration=True)
    token_with_audience = jwt.new_raw_jwt(
        audiences=['audience'], without_expiration=True)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token_with_audience)

  def test_no_audience_success(self):
    validator = jwt.new_validator(allow_missing_expiration=True)
    token = jwt.new_raw_jwt(without_expiration=True)
    _jwt_validator.validate(validator, token)

  def test_ignore_audiences_success(self):
    validator = jwt.new_validator(
        ignore_audiences=True, allow_missing_expiration=True)
    token_without_audience = jwt.new_raw_jwt(without_expiration=True)
    _jwt_validator.validate(validator, token_without_audience)
    token_with_audience = jwt.new_raw_jwt(
        audiences=['audience'], without_expiration=True)
    _jwt_validator.validate(validator, token_with_audience)

  def test_validate_with_fixed_now_expired_fails(self):
    in_two_minutes = (
        datetime.datetime.now(tz=datetime.timezone.utc) +
        datetime.timedelta(minutes=2))
    in_one_minute = in_two_minutes - datetime.timedelta(minutes=1)
    token = jwt.new_raw_jwt(expiration=in_one_minute)
    validator = jwt.new_validator(fixed_now=in_two_minutes)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_validate_with_fixed_now_not_yet_valid_fails(self):
    two_minutes_ago = (
        datetime.datetime.now(tz=datetime.timezone.utc) -
        datetime.timedelta(minutes=2))
    one_minute_ago = two_minutes_ago + datetime.timedelta(minutes=1)
    token = jwt.new_raw_jwt(not_before=one_minute_ago, without_expiration=True)
    validator = jwt.new_validator(fixed_now=two_minutes_ago)
    with self.assertRaises(jwt.JwtInvalidError):
      _jwt_validator.validate(validator, token)

  def test_validate_with_fixed_now_valid_success(self):
    fixed_now = datetime.datetime.fromtimestamp(12345, datetime.timezone.utc)
    validator = jwt.new_validator(fixed_now=fixed_now)
    expiration = fixed_now + datetime.timedelta(minutes=1)
    not_before = fixed_now - datetime.timedelta(minutes=1)
    token = jwt.new_raw_jwt(expiration=expiration, not_before=not_before)
    _jwt_validator.validate(validator, token)

  def test_validators_with_expected_and_ignored_fail(self):
    with self.assertRaises(ValueError):
      jwt.new_validator(expected_issuer='a', ignore_issuer=True)
    with self.assertRaises(ValueError):
      jwt.new_validator(expected_subject='a', ignore_subject=True)
    with self.assertRaises(ValueError):
      jwt.new_validator(expected_audience='a', ignore_audiences=True)

  def test_invalid_clock_skew_fail(self):
    with self.assertRaises(ValueError):
      jwt.new_validator(clock_skew=datetime.timedelta(minutes=1000))

  def test_fixed_now_without_timezone_fail(self):
    with self.assertRaises(ValueError):
      jwt.new_validator(fixed_now=datetime.datetime.fromtimestamp(12345))


if __name__ == '__main__':
  absltest.main()
