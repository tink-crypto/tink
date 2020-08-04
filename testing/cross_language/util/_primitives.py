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

import io
from typing import BinaryIO, Mapping, Text
from absl import logging

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
    logging.info('encrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=self._keyset,
        plaintext=plaintext,
        associated_data=associated_data)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      logging.info('error encrypt in %s: %s', self.lang, enc_response.err)
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    logging.info('decrypt in lang %s.', self.lang)
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=self._keyset,
        ciphertext=ciphertext,
        associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
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
    logging.info('encrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.DeterministicAeadEncryptRequest(
        keyset=self._keyset,
        plaintext=plaintext,
        associated_data=associated_data)
    enc_response = self._stub.EncryptDeterministically(enc_request)
    if enc_response.err:
      logging.info('error encrypt in %s: %s', self.lang, enc_response.err)
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext

  def decrypt_deterministically(self, ciphertext: bytes,
                                associated_data: bytes) -> bytes:
    """Decrypts."""
    logging.info('decrypt in lang %s.', self.lang)
    dec_request = testing_api_pb2.DeterministicAeadDecryptRequest(
        keyset=self._keyset,
        ciphertext=ciphertext,
        associated_data=associated_data)
    dec_response = self._stub.DecryptDeterministically(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
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
    logging.info('encrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.StreamingAeadEncryptRequest(
        keyset=self._keyset,
        plaintext=plaintext.read(),
        associated_data=associated_data)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      logging.info('error encrypt in %s: %s', self.lang, enc_response.err)
      raise tink.TinkError(enc_response.err)
    return io.BytesIO(enc_response.ciphertext)

  def new_decrypting_stream(self, ciphertext: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    logging.info('decrypt in lang %s.', self.lang)
    dec_request = testing_api_pb2.StreamingAeadDecryptRequest(
        keyset=self._keyset,
        ciphertext=ciphertext.read(),
        associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
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
    logging.info('compute_mac in lang %s.', self.lang)
    request = testing_api_pb2.ComputeMacRequest(keyset=self._keyset, data=data)
    response = self._stub.ComputeMac(request)
    if response.err:
      logging.info('error compute_mac in %s: %s', self.lang, response.err)
      raise tink.TinkError(response.err)
    return response.mac_value

  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    logging.info('verify_mac in lang %s.', self.lang)
    request = testing_api_pb2.VerifyMacRequest(
        keyset=self._keyset, mac_value=mac_value, data=data)
    response = self._stub.VerifyMac(request)
    if response.err:
      logging.info('error verify_mac in %s: %s', self.lang, response.err)
      raise tink.TinkError(response.err)


class HybridEncrypt(hybrid.HybridEncrypt):
  """Implements the HybridEncrypt primitive using a hybrid service stub."""

  def __init__(self, lang: Text, stub: testing_api_pb2_grpc.HybridStub,
               public_handle: bytes) -> None:
    self.lang = lang
    self._stub = stub
    self._public_handle = public_handle

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    logging.info('hybrid Sencrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.HybridEncryptRequest(
        public_keyset=self._public_handle,
        plaintext=plaintext,
        context_info=context_info)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      logging.info('error encrypt in %s: %s', self.lang, enc_response.err)
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
    logging.info('decrypt in lang %s.', self.lang)
    dec_request = testing_api_pb2.HybridDecryptRequest(
        private_keyset=self._private_handle,
        ciphertext=ciphertext,
        context_info=context_info)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error hybriddecrypt in %s: %s', self.lang, dec_response.err)
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
    logging.info('compute_mac in lang %s.', self.lang)
    request = testing_api_pb2.SignatureSignRequest(
        private_keyset=self._private_handle, data=data)
    response = self._stub.Sign(request)
    if response.err:
      logging.info('error signature sign in %s: %s', self.lang, response.err)
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
    logging.info('signature verify in lang %s.', self.lang)
    request = testing_api_pb2.SignatureVerifyRequest(
        public_keyset=self._public_handle, signature=signature, data=data)
    response = self._stub.Verify(request)
    if response.err:
      logging.info('error signature verify in %s: %s', self.lang, response.err)
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
    logging.info('Compute PRF in lang %s.', self.lang)
    request = testing_api_pb2.PrfSetComputeRequest(
        keyset=self._keyset,
        key_id=self._key_id,
        input_data=input_data,
        output_length=output_length)
    response = self._stub.Compute(request)
    if response.err:
      logging.info('Error compute PRF in %s: %s', self.lang, response.err)
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
      logging.info('Get PrfSet key IDs in lang %s.', self.lang)
      request = testing_api_pb2.PrfSetKeyIdsRequest(keyset=self._keyset)
      response = self._stub.KeyIds(request)
      if response.err:
        logging.info('Error PrfSet KeyIds in %s: %s', self.lang, response.err)
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
