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
"""Testing service API implementations in Python."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io

import grpc
import tink
from tink import aead
from tink import cleartext_keyset_handle
from tink import daead
from tink import mac
from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc


class MetadataServicer(testing_api_pb2_grpc.MetadataServicer):
  """A service with metadata about the server."""

  def GetServerInfo(
      self, request: testing_api_pb2.ServerInfoRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.ServerInfoResponse:
    """Generates a keyset."""
    return testing_api_pb2.ServerInfoResponse(language='python')


class KeysetServicer(testing_api_pb2_grpc.KeysetServicer):
  """A service for testing Keyset operations."""

  def Generate(
      self, request: testing_api_pb2.KeysetGenerateRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.KeysetGenerateResponse:
    """Generates a keyset."""
    try:
      template = tink_pb2.KeyTemplate()
      template.ParseFromString(request.template)
      keyset_handle = tink.new_keyset_handle(template)
      keyset = io.BytesIO()
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(keyset), keyset_handle)
      return testing_api_pb2.KeysetGenerateResponse(keyset=keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetGenerateResponse(err=str(e))


class AeadServicer(testing_api_pb2_grpc.AeadServicer):
  """A service for testing AEAD encryption."""

  def Encrypt(
      self, request: testing_api_pb2.AeadEncryptRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.AeadEncryptResponse:
    """Encrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(aead.Aead)
      ciphertext = p.encrypt(request.plaintext, request.associated_data)
      return testing_api_pb2.AeadEncryptResponse(ciphertext=ciphertext)
    except tink.TinkError as e:
      return testing_api_pb2.AeadEncryptResponse(err=str(e))

  def Decrypt(
      self, request: testing_api_pb2.AeadDecryptRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.AeadDecryptResponse:
    """Decrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(aead.Aead)
      plaintext = p.decrypt(request.ciphertext, request.associated_data)
      return testing_api_pb2.AeadDecryptResponse(plaintext=plaintext)
    except tink.TinkError as e:
      return testing_api_pb2.AeadDecryptResponse(err=str(e))


class DeterministicAeadServicer(testing_api_pb2_grpc.DeterministicAeadServicer):
  """A service for testing Deterministic AEAD encryption."""

  def EncryptDeterministically(
      self, request: testing_api_pb2.DeterministicAeadEncryptRequest,
      context: grpc.ServicerContext
  ) -> testing_api_pb2.DeterministicAeadEncryptResponse:
    """Encrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(daead.DeterministicAead)
      ciphertext = p.encrypt_deterministically(request.plaintext,
                                               request.associated_data)
      return testing_api_pb2.DeterministicAeadEncryptResponse(
          ciphertext=ciphertext)
    except tink.TinkError as e:
      return testing_api_pb2.DeterministicAeadEncryptResponse(err=str(e))

  def DecryptDeterministically(
      self, request: testing_api_pb2.DeterministicAeadDecryptRequest,
      context: grpc.ServicerContext
  ) -> testing_api_pb2.DeterministicAeadDecryptResponse:
    """Decrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(daead.DeterministicAead)
      plaintext = p.decrypt_deterministically(request.ciphertext,
                                              request.associated_data)
      return testing_api_pb2.DeterministicAeadDecryptResponse(
          plaintext=plaintext)
    except tink.TinkError as e:
      return testing_api_pb2.DeterministicAeadDecryptResponse(err=str(e))


class MacServicer(testing_api_pb2_grpc.MacServicer):
  """A service for testing MACs."""

  def ComputeMac(
      self, request: testing_api_pb2.ComputeMacRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.ComputeMacResponse:
    """Computes a MAC."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(mac.Mac)
      mac_value = p.compute_mac(request.data)
      return testing_api_pb2.ComputeMacResponse(mac_value=mac_value)
    except tink.TinkError as e:
      return testing_api_pb2.ComputeMacResponse(err=str(e))

  def VerifyMac(
      self, request: testing_api_pb2.VerifyMacRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.VerifyMacResponse:
    """Verifies a MAC value."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(mac.Mac)
      p.verify_mac(request.mac_value, request.data)
      return testing_api_pb2.VerifyMacResponse()
    except tink.TinkError as e:
      return testing_api_pb2.VerifyMacResponse(err=str(e))
