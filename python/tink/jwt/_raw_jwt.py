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
"""The raw JSON Web Token (JWT)."""

import copy
import datetime
import json

from typing import cast, Mapping, Set, List, Dict, Optional, Union, Any

from tink import core
from tink.jwt import _json_util
from tink.jwt import _jwt_error

_REGISTERED_NAMES = frozenset({'iss', 'sub', 'jti', 'aud', 'exp', 'nbf', 'iat'})

_MAX_TIMESTAMP_VALUE = 253402300799  # 31 Dec 9999, 23:59:59 GMT

Claim = Union[None, bool, int, float, str, List[Any], Dict[str, Any]]


def _from_datetime(t: datetime.datetime) -> int:
  if not t.tzinfo:
    raise _jwt_error.JwtInvalidError('datetime must have tzinfo')
  return int(t.timestamp())


def _to_datetime(timestamp: float) -> datetime.datetime:
  return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)


def _validate_custom_claim_name(name: str) -> None:
  if name in _REGISTERED_NAMES:
    raise _jwt_error.JwtInvalidError(
        'registered name %s cannot be custom claim name' % name)


class RawJwt:
  """An unencoded and unsigned JSON Web Token (JWT).

  It contains all payload claims and a subset of the headers. It does not
  contain any headers that depend on the key, such as "alg" or "kid", because
  these headers are chosen when the token is signed and encoded, and should not
  be chosen by the user. This ensures that the key can be changed without any
  changes to the user code.
  """

  def __new__(cls):
    raise core.TinkError('RawJwt cannot be instantiated directly.')

  def __init__(self, type_header: Optional[str], payload: Any) -> None:
    # No need to copy payload, because only create and from_json_payload
    # call this method.
    if not isinstance(payload, Dict):
      raise _jwt_error.JwtInvalidError('payload must be a dict')
    self._type_header = type_header
    self._payload = payload
    self._validate_string_claim('iss')
    self._validate_string_claim('sub')
    self._validate_string_claim('jti')
    self._validate_timestamp_claim('exp')
    self._validate_timestamp_claim('nbf')
    self._validate_timestamp_claim('iat')
    self._validate_audience_claim()

  def _validate_string_claim(self, name: str):
    if name in self._payload:
      if not isinstance(self._payload[name], str):
        raise _jwt_error.JwtInvalidError('claim %s must be a String' % name)

  def _validate_timestamp_claim(self, name: str):
    if name in self._payload:
      timestamp = self._payload[name]
      if not isinstance(timestamp, (int, float)):
        raise _jwt_error.JwtInvalidError('claim %s must be a Number' % name)
      if timestamp > _MAX_TIMESTAMP_VALUE or timestamp < 0:
        raise _jwt_error.JwtInvalidError(
            'timestamp of claim %s is out of range' % name)

  def _validate_audience_claim(self):
    """The 'aud' claim must either be a string or a list of strings."""
    if 'aud' in self._payload:
      audiences = self._payload['aud']
      if isinstance(audiences, str):
        return
      if not isinstance(audiences, list) or not audiences:
        raise _jwt_error.JwtInvalidError('audiences cannot be an empty list')
      if not all(isinstance(value, str) for value in audiences):
        raise _jwt_error.JwtInvalidError('audiences must only contain strings')

  def has_type_header(self) -> bool:
    return self._type_header is not None

  def type_header(self) -> str:
    if self._type_header is None:
      raise KeyError('type header is not set')
    return self._type_header

  def has_issuer(self) -> bool:
    return 'iss' in self._payload

  def issuer(self) -> str:
    return cast(str, self._payload['iss'])

  def has_subject(self) -> bool:
    return 'sub' in self._payload

  def subject(self) -> str:
    return cast(str, self._payload['sub'])

  def has_audiences(self) -> bool:
    return 'aud' in self._payload

  def audiences(self) -> List[str]:
    aud = self._payload['aud']
    if isinstance(aud, str):
      return [aud]
    return list(aud)

  def has_jwt_id(self) -> bool:
    return 'jti' in self._payload

  def jwt_id(self) -> str:
    return cast(str, self._payload['jti'])

  def has_expiration(self) -> bool:
    return 'exp' in self._payload

  def expiration(self) -> datetime.datetime:
    return _to_datetime(self._payload['exp'])

  def has_not_before(self) -> bool:
    return 'nbf' in self._payload

  def not_before(self) -> datetime.datetime:
    return _to_datetime(self._payload['nbf'])

  def has_issued_at(self) -> bool:
    return 'iat' in self._payload

  def issued_at(self) -> datetime.datetime:
    return _to_datetime(self._payload['iat'])

  def custom_claim_names(self) -> Set[str]:
    return {n for n in self._payload.keys() if n not in _REGISTERED_NAMES}

  def custom_claim(self, name: str) -> Claim:
    _validate_custom_claim_name(name)
    value = self._payload[name]
    if isinstance(value, (list, dict)):
      return copy.deepcopy(value)
    else:
      return value

  def json_payload(self) -> str:
    """Returns the payload encoded as JSON string."""
    return _json_util.json_dumps(self._payload)

  @classmethod
  def create(cls,
             *,
             type_header: Optional[str] = None,
             issuer: Optional[str] = None,
             subject: Optional[str] = None,
             audience: Optional[str] = None,
             audiences: Optional[List[str]] = None,
             jwt_id: Optional[str] = None,
             expiration: Optional[datetime.datetime] = None,
             without_expiration: Optional[bool] = None,
             not_before: Optional[datetime.datetime] = None,
             issued_at: Optional[datetime.datetime] = None,
             custom_claims: Optional[Mapping[str, Claim]] = None) -> 'RawJwt':
    """Create a new RawJwt instance."""
    if not expiration and not without_expiration:
      raise ValueError('either expiration or without_expiration must be set')
    if expiration and without_expiration:
      raise ValueError(
          'expiration and without_expiration cannot be set at the same time')
    if audience is not None and audiences is not None:
      raise _jwt_error.JwtInvalidError(
          'audience and audiences cannot be set at the same time')
    payload: Dict[str, Any] = {}
    if issuer:
      payload['iss'] = issuer
    if subject:
      payload['sub'] = subject
    if jwt_id is not None:
      payload['jti'] = jwt_id
    if audience is not None:
      payload['aud'] = audience
    if audiences is not None:
      payload['aud'] = copy.copy(audiences)
    if expiration:
      payload['exp'] = _from_datetime(expiration)
    if not_before:
      payload['nbf'] = _from_datetime(not_before)
    if issued_at:
      payload['iat'] = _from_datetime(issued_at)
    if custom_claims:
      for name, value in custom_claims.items():
        _validate_custom_claim_name(name)
        if not isinstance(name, str):
          raise _jwt_error.JwtInvalidError('claim name must be Text')
        if (value is None or isinstance(value, (bool, int, float, str))):
          payload[name] = value
        elif isinstance(value, list):
          payload[name] = json.loads(json.dumps(value))
        elif isinstance(value, dict):
          payload[name] = json.loads(json.dumps(value))
        else:
          raise _jwt_error.JwtInvalidError('claim %s has unknown type' % name)
    raw_jwt = object.__new__(cls)
    raw_jwt.__init__(type_header, payload)
    return raw_jwt

  @classmethod
  def _from_json(cls, type_header: Optional[str], payload: str) -> 'RawJwt':
    """Creates a RawJwt from payload encoded as JSON string."""
    raw_jwt = object.__new__(cls)
    raw_jwt.__init__(type_header, _json_util.json_loads(payload))
    return raw_jwt


def new_raw_jwt(*,
                type_header: Optional[str] = None,
                issuer: Optional[str] = None,
                subject: Optional[str] = None,
                audience: Optional[str] = None,
                audiences: Optional[List[str]] = None,
                jwt_id: Optional[str] = None,
                expiration: Optional[datetime.datetime] = None,
                without_expiration: bool = False,
                not_before: Optional[datetime.datetime] = None,
                issued_at: Optional[datetime.datetime] = None,
                custom_claims: Optional[Mapping[str, Claim]] = None) -> RawJwt:
  """Creates a new RawJwt."""
  return RawJwt.create(
      type_header=type_header,
      issuer=issuer,
      subject=subject,
      audience=audience,
      audiences=audiences,
      jwt_id=jwt_id,
      expiration=expiration,
      without_expiration=without_expiration,
      not_before=not_before,
      issued_at=issued_at,
      custom_claims=custom_claims)


def raw_jwt_from_json(type_header: Optional[str], payload: str) -> RawJwt:
  """Internal function used to verify JWT token."""
  return RawJwt._from_json(type_header, payload)  # pylint: disable=protected-access
