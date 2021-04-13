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
"""The JwtValidator."""

import datetime

from typing import Optional, Text
from tink.jwt import _jwt_error
from tink.jwt import _raw_jwt

_MAX_CLOCK_SKEW = datetime.timedelta(minutes=10)


class JwtValidator(object):
  """A JwtValidator defines how JSON Web Tokens (JWTs) should be validated.

    - If issuer is set, only tokens with the same issuer set are accepted.
    - If subject is set, only tokens with the same subject set are accepted.
    - If audience is set, only tokens that contain that audience in their
      audiences are accepted. Furthermore, if audience is not set, only
      tokens without audiences set are accepted.
    - If tokens have expiration and/or not_before set, they will be
      validated using the current datetime. If fixed_now is set, that datetime
      is used for validation instead of the current time.
    - clock_skew can be set to allow a small leeway (not more than 10 minutes)
      to account for clock skew.
  """

  def __init__(self,
               issuer: Optional[Text] = None,
               subject: Optional[Text] = None,
               audience: Optional[Text] = None,
               clock_skew: Optional[datetime.timedelta] = None,
               fixed_now: Optional[datetime.datetime] = None) -> None:
    self._issuer = issuer
    self._subject = subject
    self._audience = audience
    if clock_skew:
      if clock_skew > _MAX_CLOCK_SKEW:
        raise ValueError('clock skew too large, max is 10 minutes')
      self._clock_skew = clock_skew
    else:
      self._clock_skew = datetime.timedelta()
    if fixed_now and not fixed_now.tzinfo:
      raise ValueError('fixed_now without tzinfo')
    self._fixed_now = fixed_now

  def has_issuer(self) -> bool:
    return self._issuer is not None

  def issuer(self) -> Text:
    return self._issuer

  def has_subject(self) -> bool:
    return self._subject is not None

  def subject(self) -> Text:
    return self._subject

  def has_audience(self) -> bool:
    return self._audience is not None

  def audience(self) -> Text:
    return self._audience

  def clock_skew(self) -> datetime.timedelta:
    return self._clock_skew

  def has_fixed_now(self) -> bool:
    return self._fixed_now is not None

  def fixed_now(self) -> datetime.datetime:
    return self._fixed_now


def validate(validator: JwtValidator, raw_jwt: _raw_jwt.RawJwt) -> None:
  """Validates a jwt.RawJwt and raises JwtInvalidError if it is invalid.

  This function is called by the JWT primitives and does not need to be called
  by the user.

  Args:
    validator: a jwt.JwtValidator that defines how to validate tokens.
    raw_jwt: a jwt.RawJwt token to validate.
  Raises:
    jwt.JwtInvalidError
  """
  if validator.has_fixed_now():
    now = validator.fixed_now()
  else:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
  if (raw_jwt.has_expiration() and
      raw_jwt.expiration() < now - validator.clock_skew()):
    raise _jwt_error.JwtInvalidError('token has expired since %s' %
                                     raw_jwt.expiration())
  if (raw_jwt.has_not_before() and
      raw_jwt.not_before() > now + validator.clock_skew()):
    raise _jwt_error.JwtInvalidError('token cannot be used before %s' %
                                     raw_jwt.not_before())
  if validator.has_issuer():
    if not raw_jwt.has_issuer():
      raise _jwt_error.JwtInvalidError(
          'invalid JWT; missing expected issuer %s.' % validator.issuer())
    if validator.issuer() != raw_jwt.issuer():
      raise _jwt_error.JwtInvalidError(
          'invalid JWT; expected issuer %s, but got %s' %
          (validator.issuer(), raw_jwt.issuer()))
  if validator.has_subject():
    if not raw_jwt.has_subject():
      raise _jwt_error.JwtInvalidError(
          'invalid JWT; missing expected subject %s.' % validator.subject())
    if validator.subject() != raw_jwt.subject():
      raise _jwt_error.JwtInvalidError(
          'invalid JWT; expected subject %s, but got %s' %
          (validator.subject(), raw_jwt.subject()))
  if validator.has_audience():
    if (not raw_jwt.has_audiences() or
        validator.audience() not in raw_jwt.audiences()):
      raise _jwt_error.JwtInvalidError(
          'invalid JWT; missing expected audience %s.' % validator.audience())
  else:
    if raw_jwt.has_audiences():
      raise _jwt_error.JwtInvalidError(
          'invalid JWT; token has audience set, but validator not.')
