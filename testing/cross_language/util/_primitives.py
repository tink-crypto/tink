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
from typing import BinaryIO, Text
from absl import logging

import tink
from tink import aead
from tink import cleartext_keyset_handle
from tink import daead
from tink import hybrid
from tink import mac
from tink import signature as tink_signature
from tink import streaming_aead

from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc


def _keyset(keyset_handle: tink.KeysetHandle) -> bytes:
  """Returns the keyset contained in the keyset_handle."""
  keyset_buffer = io.BytesIO()
  cleartext_keyset_handle.write(
      tink.BinaryKeysetWriter(keyset_buffer), keyset_handle)
  return keyset_buffer.getvalue()


def new_keyset_handle(stub: testing_api_pb2_grpc.KeysetStub,
                      key_template: tink_pb2.KeyTemplate) -> tink.KeysetHandle:
  gen_request = testing_api_pb2.KeysetGenerateRequest(
      template=key_template.SerializeToString())
  gen_response = stub.Generate(gen_request)
  if gen_response.err:
    raise tink.TinkError(gen_response.err)
  return cleartext_keyset_handle.read(
      tink.BinaryKeysetReader(gen_response.keyset))


def public_keyset_handle(
    stub: testing_api_pb2_grpc.KeysetStub,
    private_keyset_handle: tink.KeysetHandle) -> tink.KeysetHandle:
  request = testing_api_pb2.KeysetPublicRequest(
      private_keyset=_keyset(private_keyset_handle))
  response = stub.Public(request)
  if response.err:
    raise tink.TinkError(response.err)
  return cleartext_keyset_handle.read(
      tink.BinaryKeysetReader(response.public_keyset))


class Aead(aead.Aead):
  """Wraps AEAD service stub into an Aead primitive."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.AeadStub,
               keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset_handle = keyset_handle

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    logging.info('encrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=_keyset(self._keyset_handle),
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
        keyset=_keyset(self._keyset_handle),
        ciphertext=ciphertext, associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class DeterministicAead(daead.DeterministicAead):
  """Wraps DAEAD services stub into an DeterministicAead primitive."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.DeterministicAeadStub,
               keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset_handle = keyset_handle

  def encrypt_deterministically(self, plaintext: bytes,
                                associated_data: bytes) -> bytes:
    """Encrypts."""
    logging.info('encrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.DeterministicAeadEncryptRequest(
        keyset=_keyset(self._keyset_handle),
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
        keyset=_keyset(self._keyset_handle),
        ciphertext=ciphertext, associated_data=associated_data)
    dec_response = self._stub.DecryptDeterministically(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class StreamingAead(streaming_aead.StreamingAead):
  """Wraps Streaming AEAD service stub into a StreamingAead primitive."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.StreamingAeadStub,
               keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset_handle = keyset_handle

  def new_encrypting_stream(self, plaintext: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    logging.info('encrypt in lang %s.', self.lang)
    logging.info('type(plaintext): %s', type(plaintext))
    enc_request = testing_api_pb2.StreamingAeadEncryptRequest(
        keyset=_keyset(self._keyset_handle),
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
    logging.info('type(ciphertext): %s', type(ciphertext))
    dec_request = testing_api_pb2.StreamingAeadDecryptRequest(
        keyset=_keyset(self._keyset_handle),
        ciphertext=ciphertext.read(), associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
      raise tink.TinkError(dec_response.err)
    return io.BytesIO(dec_response.plaintext)


class Mac(mac.Mac):
  """Wraps MAC service stub into an Mac primitive."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.MacStub,
               keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset_handle = keyset_handle

  def compute_mac(self, data: bytes) -> bytes:
    logging.info('compute_mac in lang %s.', self.lang)
    request = testing_api_pb2.ComputeMacRequest(
        keyset=_keyset(self._keyset_handle),
        data=data)
    response = self._stub.ComputeMac(request)
    if response.err:
      logging.info('error compute_mac in %s: %s', self.lang, response.err)
      raise tink.TinkError(response.err)
    return response.mac_value

  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    logging.info('verify_mac in lang %s.', self.lang)
    request = testing_api_pb2.VerifyMacRequest(
        keyset=_keyset(self._keyset_handle),
        mac_value=mac_value,
        data=data)
    response = self._stub.VerifyMac(request)
    if response.err:
      logging.info('error verify_mac in %s: %s', self.lang, response.err)
      raise tink.TinkError(response.err)


class HybridEncrypt(hybrid.HybridEncrypt):
  """Implements the HybridEncrypt primitive using a hybrid service stub."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.HybridStub,
               public_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._public_handle = public_handle

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    logging.info('hybrid Sencrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.HybridEncryptRequest(
        public_keyset=_keyset(self._public_handle),
        plaintext=plaintext,
        context_info=context_info)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      logging.info('error encrypt in %s: %s', self.lang, enc_response.err)
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext


class HybridDecrypt(hybrid.HybridDecrypt):
  """Implements the HybridDecrypt primitive using a hybrid service stub."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.HybridStub,
               private_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._private_handle = private_handle

  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    logging.info('decrypt in lang %s.', self.lang)
    dec_request = testing_api_pb2.HybridDecryptRequest(
        private_keyset=_keyset(self._private_handle),
        ciphertext=ciphertext, context_info=context_info)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error hybriddecrypt in %s: %s', self.lang, dec_response.err)
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class PublicKeySign(tink_signature.PublicKeySign):
  """Implements the PublicKeySign primitive using a signature service stub."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.SignatureStub,
               private_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._private_handle = private_handle

  def sign(self, data: bytes) -> bytes:
    logging.info('compute_mac in lang %s.', self.lang)
    request = testing_api_pb2.SignatureSignRequest(
        private_keyset=_keyset(self._private_handle),
        data=data)
    response = self._stub.Sign(request)
    if response.err:
      logging.info('error signature sign in %s: %s', self.lang, response.err)
      raise tink.TinkError(response.err)
    return response.signature


class PublicKeyVerify(tink_signature.PublicKeyVerify):
  """Implements the PublicKeyVerify primitive using a signature service stub."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.SignatureStub,
               public_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._public_handle = public_handle

  def verify(self, signature: bytes, data: bytes) -> None:
    logging.info('signature verify in lang %s.', self.lang)
    request = testing_api_pb2.SignatureVerifyRequest(
        public_keyset=_keyset(self._public_handle),
        signature=signature,
        data=data)
    response = self._stub.Verify(request)
    if response.err:
      logging.info('error signature verify in %s: %s', self.lang, response.err)
      raise tink.TinkError(response.err)
