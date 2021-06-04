# Copyright 2020 Google LLC
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
# limitations under the License.
"""Implements tink primitives from gRPC testing_api stubs."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import datetime
import io
import json
from typing import BinaryIO, Mapping, Text, Tuple

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature as tink_signature
from tink import streaming_aead

from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc

from tink import jwt


def new_keyset(stub: testing_api_pb2_grpc.KeysetStub,
               key_template: tink_pb2.KeyTemplate) -> bytes:
  gen_request = testing_api_pb2.KeysetGenerateRequest(
      template=key_template.SerializeToString())
  gen_response = stub.Generate(gen_request)
  if gen_response.err:
    raise tink.TinkError(gen_response.err)
  return gen_response.keyset


def public_keyset(stub: testing_api_pb2_grpc.KeysetStub,
                  private_keyset: bytes) -> bytes:
  request = testing_api_pb2.KeysetPublicRequest(private_keyset=private_keyset)
  response = stub.Public(request)
  if response.err:
    raise tink.TinkError(response.err)
  return response.public_keyset


def keyset_to_json(
    stub: testing_api_pb2_grpc.KeysetStub,
    keyset: bytes) -> Text:
  request = testing_api_pb2.KeysetToJsonRequest(keyset=keyset)
  response = stub.ToJson(request)
  if response.err:
    raise tink.TinkError(response.err)
  return response.json_keyset


def keyset_from_json(
    stub: testing_api_pb2_grpc.KeysetStub,
    json_keyset: Text) -> bytes:
  request = testing_api_pb2.KeysetFromJsonRequest(json_keyset=json_keyset)
  response = stub.FromJson(request)
  if response.err:
    raise tink.TinkError(response.err)
  return response.keyset


class Aead(aead.Aead):
  """Wraps AEAD service stub into an Aead primitive."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.AeadStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=self._keyset,
        plaintext=plaintext,
        associated_data=associated_data)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=self._keyset,
        ciphertext=ciphertext,
        associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class DeterministicAead(daead.DeterministicAead):
  """Wraps DAEAD services stub into an DeterministicAead primitive."""

  def __init__(self, lang: Text,
               stub: testing_api_pb2_grpc.DeterministicAeadStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def encrypt_deterministically(self, plaintext: bytes,
                                associated_data: bytes) -> bytes:
    """Encrypts."""
    enc_request = testing_api_pb2.DeterministicAeadEncryptRequest(
        keyset=self._keyset,
        plaintext=plaintext,
        associated_data=associated_data)
    enc_response = self._stub.EncryptDeterministically(enc_request)
    if enc_response.err:
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext

  def decrypt_deterministically(self, ciphertext: bytes,
                                associated_data: bytes) -> bytes:
    """Decrypts."""
    dec_request = testing_api_pb2.DeterministicAeadDecryptRequest(
        keyset=self._keyset,
        ciphertext=ciphertext,
        associated_data=associated_data)
    dec_response = self._stub.DecryptDeterministically(dec_request)
    if dec_response.err:
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class StreamingAead(streaming_aead.StreamingAead):
  """Wraps Streaming AEAD service stub into a StreamingAead primitive."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.StreamingAeadStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def new_encrypting_stream(self, plaintext: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    enc_request = testing_api_pb2.StreamingAeadEncryptRequest(
        keyset=self._keyset,
        plaintext=plaintext.read(),
        associated_data=associated_data)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      raise tink.TinkError(enc_response.err)
    return io.BytesIO(enc_response.ciphertext)

  def new_decrypting_stream(self, ciphertext: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    dec_request = testing_api_pb2.StreamingAeadDecryptRequest(
        keyset=self._keyset,
        ciphertext=ciphertext.read(),
        associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      raise tink.TinkError(dec_response.err)
    return io.BytesIO(dec_response.plaintext)


class Mac(mac.Mac):
  """Wraps MAC service stub into an Mac primitive."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.MacStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def compute_mac(self, data: bytes) -> bytes:
    request = testing_api_pb2.ComputeMacRequest(keyset=self._keyset, data=data)
    response = self._stub.ComputeMac(request)
    if response.err:
      raise tink.TinkError(response.err)
    return response.mac_value

  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    request = testing_api_pb2.VerifyMacRequest(
        keyset=self._keyset, mac_value=mac_value, data=data)
    response = self._stub.VerifyMac(request)
    if response.err:
      raise tink.TinkError(response.err)


class HybridEncrypt(hybrid.HybridEncrypt):
  """Implements the HybridEncrypt primitive using a hybrid service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.HybridStub,
               public_handle: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._public_handle = public_handle

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    enc_request = testing_api_pb2.HybridEncryptRequest(
        public_keyset=self._public_handle,
        plaintext=plaintext,
        context_info=context_info)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext


class HybridDecrypt(hybrid.HybridDecrypt):
  """Implements the HybridDecrypt primitive using a hybrid service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.HybridStub,
               private_handle: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._private_handle = private_handle

  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    dec_request = testing_api_pb2.HybridDecryptRequest(
        private_keyset=self._private_handle,
        ciphertext=ciphertext,
        context_info=context_info)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class PublicKeySign(tink_signature.PublicKeySign):
  """Implements the PublicKeySign primitive using a signature service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.SignatureStub,
               private_handle: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._private_handle = private_handle

  def sign(self, data: bytes) -> bytes:
    request = testing_api_pb2.SignatureSignRequest(
        private_keyset=self._private_handle, data=data)
    response = self._stub.Sign(request)
    if response.err:
      raise tink.TinkError(response.err)
    return response.signature


class PublicKeyVerify(tink_signature.PublicKeyVerify):
  """Implements the PublicKeyVerify primitive using a signature service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.SignatureStub,
               public_handle: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._public_handle = public_handle

  def verify(self, signature: bytes, data: bytes) -> None:
    request = testing_api_pb2.SignatureVerifyRequest(
        public_keyset=self._public_handle, signature=signature, data=data)
    response = self._stub.Verify(request)
    if response.err:
      raise tink.TinkError(response.err)


class _Prf(prf.Prf):
  """Implements a Prf from a PrfSet service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.PrfSetStub,
               keyset: bytes, key_id: int) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset
    self._key_id = key_id

  def compute(self, input_data: bytes, output_length: int) -> bytes:
    request = testing_api_pb2.PrfSetComputeRequest(
        keyset=self._keyset,
        key_id=self._key_id,
        input_data=input_data,
        output_length=output_length)
    response = self._stub.Compute(request)
    if response.err:
      raise tink.TinkError(response.err)
    return response.output


class PrfSet(prf.PrfSet):
  """Implements a PrfSet from a PrfSet service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.PrfSetStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset
    self._key_ids_initialized = False
    self._primary_key_id = None
    self._prfs = None

  def _initialize_key_ids(self) -> None:
    if not self._key_ids_initialized:
      request = testing_api_pb2.PrfSetKeyIdsRequest(keyset=self._keyset)
      response = self._stub.KeyIds(request)
      if response.err:
        raise tink.TinkError(response.err)
      self._primary_key_id = response.output.primary_key_id
      self._prfs = {}
      for key_id in response.output.key_id:
        self._prfs[key_id] = _Prf(self.lang, self._stub, self._keyset, key_id)
      self._key_ids_initialized = True

  def primary_id(self) -> int:
    self._initialize_key_ids()
    return self._primary_key_id

  def all(self) -> Mapping[int, prf.Prf]:
    self._initialize_key_ids()
    return self._prfs.copy()

  def primary(self) -> prf.Prf:
    self._initialize_key_ids()
    return self._prfs[self._primary_key_id]


def split_datetime(dt: datetime.datetime) -> Tuple[int, int]:
  t = dt.timestamp()
  seconds = int(t)
  nanos = int((t - seconds) * 1e9)
  return (seconds, nanos)


def to_datetime(seconds: int, nanos: int) -> datetime.datetime:
  t = seconds + (nanos / 1e9)
  return datetime.datetime.fromtimestamp(t, datetime.timezone.utc)


def raw_jwt_to_proto(raw_jwt: jwt.RawJwt) -> testing_api_pb2.JwtToken:
  """Converts a jwt.RawJwt into a proto."""
  raw_token = testing_api_pb2.JwtToken()
  if raw_jwt.has_type_header():
    raw_token.type_header.value = raw_jwt.type_header()
  if raw_jwt.has_issuer():
    raw_token.issuer.value = raw_jwt.issuer()
  if raw_jwt.has_subject():
    raw_token.subject.value = raw_jwt.subject()
  if raw_jwt.has_audiences():
    raw_token.audiences.extend(raw_jwt.audiences())
  if raw_jwt.has_jwt_id():
    raw_token.jwt_id.value = raw_jwt.jwt_id()
  if raw_jwt.has_expiration():
    seconds, nanos = split_datetime(raw_jwt.expiration())
    raw_token.expiration.seconds = seconds
    raw_token.expiration.nanos = nanos
  if raw_jwt.has_not_before():
    seconds, nanos = split_datetime(raw_jwt.not_before())
    raw_token.not_before.seconds = seconds
    raw_token.not_before.nanos = nanos
  if raw_jwt.has_issued_at():
    seconds, nanos = split_datetime(raw_jwt.issued_at())
    raw_token.issued_at.seconds = seconds
    raw_token.issued_at.nanos = nanos
  for name in raw_jwt.custom_claim_names():
    value = raw_jwt.custom_claim(name)
    if value is None:
      raw_token.custom_claims[name].null_value = testing_api_pb2.NULL_VALUE
    if isinstance(value, (int, float)):
      raw_token.custom_claims[name].number_value = value
    if isinstance(value, Text):
      raw_token.custom_claims[name].string_value = value
    if isinstance(value, bool):
      raw_token.custom_claims[name].bool_value = value
    if isinstance(value, dict):
      raw_token.custom_claims[name].json_object_value = json.dumps(value)
    if isinstance(value, list):
      raw_token.custom_claims[name].json_array_value = json.dumps(value)
  return raw_token


def proto_to_verified_jwt(
    token: testing_api_pb2.JwtToken) -> jwt.VerifiedJwt:
  """Converts a proto JwtToken into a jwt.VerifiedJwt."""
  type_header = None
  if token.HasField('type_header'):
    type_header = token.type_header.value
  issuer = None
  if token.HasField('issuer'):
    issuer = token.issuer.value
  subject = None
  if token.HasField('subject'):
    subject = token.subject.value
  jwt_id = None
  if token.HasField('jwt_id'):
    jwt_id = token.jwt_id.value
  audiences = None
  if token.audiences:
    audiences = list(token.audiences)
  if token.HasField('expiration'):
    expiration = to_datetime(token.expiration.seconds, token.expiration.nanos)
    without_expiration = False
  else:
    expiration = None
    without_expiration = True
  not_before = None
  if token.HasField('not_before'):
    not_before = to_datetime(token.not_before.seconds, token.not_before.nanos)
  issued_at = None
  if token.HasField('issued_at'):
    issued_at = to_datetime(token.issued_at.seconds, token.issued_at.nanos)
  custom_claims = {}
  for name in token.custom_claims:
    value = token.custom_claims[name]
    if value.HasField('null_value'):
      custom_claims[name] = None
    if value.HasField('number_value'):
      custom_claims[name] = value.number_value
    if value.HasField('string_value'):
      custom_claims[name] = value.string_value
    if value.HasField('bool_value'):
      custom_claims[name] = value.bool_value
    if value.HasField('json_object_value'):
      custom_claims[name] = json.loads(value.json_object_value)
    if value.HasField('json_array_value'):
      custom_claims[name] = json.loads(value.json_array_value)
  raw_jwt = jwt.new_raw_jwt(
      type_header=type_header,
      issuer=issuer,
      subject=subject,
      audiences=audiences,
      jwt_id=jwt_id,
      expiration=expiration,
      without_expiration=without_expiration,
      not_before=not_before,
      issued_at=issued_at,
      custom_claims=custom_claims)
  return jwt.VerifiedJwt._create(raw_jwt)  # pylint: disable=protected-access


def jwt_validator_to_proto(
    validator: jwt.JwtValidator) -> testing_api_pb2.JwtValidator:
  """Converts a jwt.JwtValidator into a proto JwtValidator."""
  proto_validator = testing_api_pb2.JwtValidator()
  if validator.has_expected_issuer():
    proto_validator.issuer.value = validator.expected_issuer()
  if validator.has_expected_subject():
    proto_validator.subject.value = validator.expected_subject()
  if validator.has_expected_audience():
    proto_validator.audience.value = validator.expected_audience()
  proto_validator.clock_skew.seconds = validator.clock_skew().seconds
  if validator.has_fixed_now():
    seconds, nanos = split_datetime(validator.fixed_now())
    proto_validator.now.seconds = seconds
    proto_validator.now.nanos = nanos
  return proto_validator


class JwtMac():
  """Implements a JwtMac from a Jwt service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.JwtStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def compute_mac_and_encode(self, raw_jwt: jwt.RawJwt) -> Text:
    request = testing_api_pb2.JwtSignRequest(
        keyset=self._keyset, raw_jwt=raw_jwt_to_proto(raw_jwt))
    response = self._stub.ComputeMacAndEncode(request)
    if response.err:
      raise tink.TinkError(response.err)
    return response.signed_compact_jwt

  def verify_mac_and_decode(self, signed_compact_jwt: Text,
                            validator: jwt.JwtValidator) -> jwt.VerifiedJwt:
    request = testing_api_pb2.JwtVerifyRequest(
        keyset=self._keyset,
        validator=jwt_validator_to_proto(validator),
        signed_compact_jwt=signed_compact_jwt)
    response = self._stub.VerifyMacAndDecode(request)
    if response.err:
      raise tink.TinkError(response.err)
    return proto_to_verified_jwt(response.verified_jwt)


class JwtPublicKeySign():
  """Implements a JwtPublicKeySign from a Jwt service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.JwtStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def sign_and_encode(self, raw_jwt: jwt.RawJwt) -> Text:
    request = testing_api_pb2.JwtSignRequest(
        keyset=self._keyset, raw_jwt=raw_jwt_to_proto(raw_jwt))
    response = self._stub.PublicKeySignAndEncode(request)
    if response.err:
      raise tink.TinkError(response.err)
    return response.signed_compact_jwt


class JwtPublicKeyVerify():
  """Implements a JwtPublicKeyVerify from a Jwt service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.JwtStub,
               keyset: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset = keyset

  def verify_and_decode(self, signed_compact_jwt: Text,
                        validator: jwt.JwtValidator) -> jwt.VerifiedJwt:
    request = testing_api_pb2.JwtVerifyRequest(
        keyset=self._keyset,
        validator=jwt_validator_to_proto(validator),
        signed_compact_jwt=signed_compact_jwt)
    response = self._stub.PublicKeyVerifyAndDecode(request)
    if response.err:
      raise tink.TinkError(response.err)
    return proto_to_verified_jwt(response.verified_jwt)
