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
"""JWT testing service API implementations in Python."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import datetime
import json

from typing import Text, Tuple

import grpc
import tink
from tink import cleartext_keyset_handle

from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc

from tink import jwt


def _to_timestamp_tuple(t: datetime.datetime) -> Tuple[int, int]:
  if not t.tzinfo:
    raise ValueError('datetime must have tzinfo')
  seconds = int(t.timestamp())
  nanos = int((t.timestamp() - seconds) * 1e9)
  return (seconds, nanos)


def _from_timestamp_proto(
    timestamp: testing_api_pb2.Timestamp) -> datetime.datetime:
  t = timestamp.seconds + (timestamp.nanos / 1e9)
  return datetime.datetime.fromtimestamp(t, datetime.timezone.utc)


def _from_duration_proto(
    duration: testing_api_pb2.Duration) -> datetime.timedelta:
  return datetime.timedelta(seconds=duration.seconds)


def raw_jwt_from_proto(proto_raw_jwt: testing_api_pb2.JwtToken) -> jwt.RawJwt:
  """Converts a proto JwtToken into a jwt.RawJwt."""
  type_header = None
  if proto_raw_jwt.HasField('type_header'):
    type_header = proto_raw_jwt.type_header.value
  issuer = None
  if proto_raw_jwt.HasField('issuer'):
    issuer = proto_raw_jwt.issuer.value
  subject = None
  if proto_raw_jwt.HasField('subject'):
    subject = proto_raw_jwt.subject.value
  audiences = list(proto_raw_jwt.audiences)
  if not audiences:
    audiences = None
  jwt_id = None
  if proto_raw_jwt.HasField('jwt_id'):
    jwt_id = proto_raw_jwt.jwt_id.value
  custom_claims = {}
  for name, claim in proto_raw_jwt.custom_claims.items():
    if claim.HasField('null_value'):
      custom_claims[name] = None
    elif claim.HasField('number_value'):
      custom_claims[name] = claim.number_value
    elif claim.HasField('string_value'):
      custom_claims[name] = claim.string_value
    elif claim.HasField('bool_value'):
      custom_claims[name] = claim.bool_value
    elif claim.HasField('json_object_value'):
      custom_claims[name] = json.loads(claim.json_object_value)
    elif claim.HasField('json_array_value'):
      custom_claims[name] = json.loads(claim.json_array_value)
    else:
      raise ValueError('claim %s has unknown type' % name)
  return jwt.new_raw_jwt(
      type_header=type_header,
      issuer=issuer,
      subject=subject,
      audiences=audiences,
      jwt_id=jwt_id,
      expiration=_from_timestamp_proto(proto_raw_jwt.expiration),
      not_before=_from_timestamp_proto(proto_raw_jwt.not_before),
      issued_at=_from_timestamp_proto(proto_raw_jwt.issued_at),
      custom_claims=custom_claims)


def verifiedjwt_to_proto(
    verified_jwt: jwt.VerifiedJwt) -> testing_api_pb2.JwtToken:
  """Converts a jwt.VerifiedJwt into a proto JwtToken."""
  token = testing_api_pb2.JwtToken()
  if verified_jwt.has_type_header():
    token.type_header.value = verified_jwt.type_header()
  if verified_jwt.has_issuer():
    token.issuer.value = verified_jwt.issuer()
  if verified_jwt.has_subject():
    token.subject.value = verified_jwt.subject()
  if verified_jwt.has_audiences():
    token.audiences.extend(verified_jwt.audiences())
  if verified_jwt.has_jwt_id():
    token.jwt_id.value = verified_jwt.jwt_id()
  if verified_jwt.has_expiration():
    seconds, nanos = _to_timestamp_tuple(verified_jwt.expiration())
    token.expiration.seconds = seconds
    token.expiration.nanos = nanos
  if verified_jwt.has_not_before():
    seconds, nanos = _to_timestamp_tuple(verified_jwt.not_before())
    token.not_before.seconds = seconds
    token.not_before.nanos = nanos
  if verified_jwt.has_issued_at():
    seconds, nanos = _to_timestamp_tuple(verified_jwt.issued_at())
    token.issued_at.seconds = seconds
    token.issued_at.nanos = nanos
  for name in verified_jwt.custom_claim_names():
    value = verified_jwt.custom_claim(name)
    if value is None:
      token.custom_claims[name].null_value = testing_api_pb2.NULL_VALUE
    elif isinstance(value, bool):
      token.custom_claims[name].bool_value = value
    elif isinstance(value, (int, float)):
      token.custom_claims[name].number_value = value
    elif isinstance(value, Text):
      token.custom_claims[name].string_value = value
    elif isinstance(value, dict):
      token.custom_claims[name].json_object_value = json.dumps(value)
    elif isinstance(value, list):
      token.custom_claims[name].json_array_value = json.dumps(value)
    else:
      raise ValueError('claim %s has unknown type' % name)
  return token


def validator_from_proto(
    proto_validator: testing_api_pb2.JwtValidator) -> jwt.JwtValidator:
  """Converts a proto JwtValidator into a JwtValidator."""
  issuer = None
  if proto_validator.HasField('issuer'):
    issuer = proto_validator.issuer.value
  subject = None
  if proto_validator.HasField('subject'):
    subject = proto_validator.subject.value
  audience = None
  if proto_validator.HasField('audience'):
    audience = proto_validator.audience.value
  return jwt.new_validator(
      issuer=issuer,
      subject=subject,
      audience=audience,
      fixed_now=_from_timestamp_proto(proto_validator.now),
      clock_skew=_from_duration_proto(proto_validator.clock_skew))


class JwtServicer(testing_api_pb2_grpc.JwtServicer):
  """A service for signing and verifying JWTs."""

  def ComputeMacAndEncode(
      self, request: testing_api_pb2.JwtSignRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.JwtSignResponse:
    """Computes a MACed compact JWT."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(jwt.JwtMac)
      raw_jwt = raw_jwt_from_proto(request.raw_jwt)
      signed_compact_jwt = p.compute_mac_and_encode(raw_jwt)
      return testing_api_pb2.JwtSignResponse(
          signed_compact_jwt=signed_compact_jwt)
    except tink.TinkError as e:
      return testing_api_pb2.JwtSignResponse(err=str(e))

  def VerifyMacAndDecode(
      self, request: testing_api_pb2.JwtVerifyRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.JwtVerifyResponse:
    """Verifies a MAC value."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      validator = validator_from_proto(request.validator)
      p = keyset_handle.primitive(jwt.JwtMac)
      verified_jwt = p.verify_mac_and_decode(request.signed_compact_jwt,
                                             validator)
      return testing_api_pb2.JwtVerifyResponse(
          verified_jwt=verifiedjwt_to_proto(verified_jwt))
    except tink.TinkError as e:
      return testing_api_pb2.JwtVerifyResponse(err=str(e))

  def PublicKeySignAndEncode(
      self, request: testing_api_pb2.JwtSignRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.JwtSignResponse:
    """Computes a signed compact JWT token."""
    return testing_api_pb2.JwtSignResponse(err='Not yet implemented.')

  def PublicKeyVerifyAndDecode(
      self, request: testing_api_pb2.JwtVerifyRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.JwtVerifyResponse:
    """Verifies the validity of the signed compact JWT token."""
    return testing_api_pb2.JwtVerifyResponse(err='Not yet implemented.')
