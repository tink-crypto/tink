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
from typing import Text
from absl import logging

import tink
from tink import aead
from tink import cleartext_keyset_handle

from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc


def _keyset(keyset_handle: tink.KeysetHandle) -> bytes:
  """Returns the keyset contained in the keyset_handle."""
  keyset_buffer = io.BytesIO()
  cleartext_keyset_handle.write(
      tink.BinaryKeysetWriter(keyset_buffer), keyset_handle)
  return keyset_buffer.getvalue()


class Aead(aead.Aead):
  """Wraps AEAD services stub into an Aead primitive."""

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
