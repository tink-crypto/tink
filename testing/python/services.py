# Copyright 2020 Google LLC
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
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead
from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc
from tink.testing import bytes_io


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

  def Public(
      self, request: testing_api_pb2.KeysetPublicRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.KeysetPublicResponse:
    """Generates a public-key keyset from a private-key keyset."""
    try:
      private_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.private_keyset))
      public_keyset_handle = private_keyset_handle.public_keyset_handle()
      public_keyset = io.BytesIO()
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(public_keyset), public_keyset_handle)
      return testing_api_pb2.KeysetPublicResponse(
          public_keyset=public_keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetPublicResponse(err=str(e))

  def ToJson(
      self, request: testing_api_pb2.KeysetToJsonRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.KeysetToJsonResponse:
    """Converts a keyset from binary to JSON format."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      json_keyset = io.StringIO()
      cleartext_keyset_handle.write(
          tink.JsonKeysetWriter(json_keyset), keyset_handle)
      return testing_api_pb2.KeysetToJsonResponse(
          json_keyset=json_keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetToJsonResponse(err=str(e))

  def FromJson(
      self, request: testing_api_pb2.KeysetFromJsonRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.KeysetFromJsonResponse:
    """Converts a keyset from JSON to binary format."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.JsonKeysetReader(request.json_keyset))
      keyset = io.BytesIO()
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(keyset), keyset_handle)
      return testing_api_pb2.KeysetFromJsonResponse(keyset=keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetFromJsonResponse(err=str(e))


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


class StreamingAeadServicer(testing_api_pb2_grpc.StreamingAeadServicer):
  """A service for testing StreamingAEAD encryption."""

  def Encrypt(
      self, request: testing_api_pb2.StreamingAeadEncryptRequest,
      context: grpc.ServicerContext
  ) -> testing_api_pb2.StreamingAeadEncryptResponse:
    """Encrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(streaming_aead.StreamingAead)
      ciphertext_destination = bytes_io.BytesIOWithValueAfterClose()
      with p.new_encrypting_stream(ciphertext_destination,
                                   request.associated_data) as plaintext_stream:
        plaintext_stream.write(request.plaintext)
      return testing_api_pb2.StreamingAeadEncryptResponse(
          ciphertext=ciphertext_destination.value_after_close())
    except tink.TinkError as e:
      return testing_api_pb2.StreamingAeadEncryptResponse(err=str(e))

  def Decrypt(
      self, request: testing_api_pb2.StreamingAeadDecryptRequest,
      context: grpc.ServicerContext
  ) -> testing_api_pb2.StreamingAeadDecryptResponse:
    """Decrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(streaming_aead.StreamingAead)
      stream = io.BytesIO(request.ciphertext)
      with p.new_decrypting_stream(stream, request.associated_data) as s:
        plaintext = s.read()
      return testing_api_pb2.StreamingAeadDecryptResponse(plaintext=plaintext)
    except tink.TinkError as e:
      return testing_api_pb2.StreamingAeadDecryptResponse(err=str(e))


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


class HybridServicer(testing_api_pb2_grpc.HybridServicer):
  """A service for testing hybrid encryption and decryption."""

  def Encrypt(
      self, request: testing_api_pb2.HybridEncryptRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.HybridEncryptResponse:
    """Encrypts a message."""
    try:
      public_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.public_keyset))
      p = public_keyset_handle.primitive(hybrid.HybridEncrypt)
      ciphertext = p.encrypt(request.plaintext, request.context_info)
      return testing_api_pb2.HybridEncryptResponse(ciphertext=ciphertext)
    except tink.TinkError as e:
      return testing_api_pb2.HybridEncryptResponse(err=str(e))

  def Decrypt(
      self, request: testing_api_pb2.HybridDecryptRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.HybridDecryptResponse:
    """Decrypts a message."""
    try:
      private_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.private_keyset))
      p = private_keyset_handle.primitive(hybrid.HybridDecrypt)
      plaintext = p.decrypt(request.ciphertext, request.context_info)
      return testing_api_pb2.HybridDecryptResponse(plaintext=plaintext)
    except tink.TinkError as e:
      return testing_api_pb2.HybridDecryptResponse(err=str(e))


class SignatureServicer(testing_api_pb2_grpc.SignatureServicer):
  """A service for testing signatures."""

  def Sign(
      self, request: testing_api_pb2.SignatureSignRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.SignatureSignResponse:
    """Signs a message."""
    try:
      private_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.private_keyset))
      p = private_keyset_handle.primitive(signature.PublicKeySign)
      signature_value = p.sign(request.data)
      return testing_api_pb2.SignatureSignResponse(signature=signature_value)
    except tink.TinkError as e:
      return testing_api_pb2.SignatureSignResponse(err=str(e))

  def Verify(
      self, request: testing_api_pb2.SignatureVerifyRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.SignatureVerifyResponse:
    """Verifies a signature."""
    try:
      public_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.public_keyset))
      p = public_keyset_handle.primitive(signature.PublicKeyVerify)
      p.verify(request.signature, request.data)
      return testing_api_pb2.SignatureVerifyResponse()
    except tink.TinkError as e:
      return testing_api_pb2.SignatureVerifyResponse(err=str(e))


class PrfSetServicer(testing_api_pb2_grpc.PrfSetServicer):
  """A service for testing PrfSet."""

  def KeyIds(
      self, request: testing_api_pb2.PrfSetKeyIdsRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.PrfSetKeyIdsResponse:
    """Returns all key IDs and the primary key ID."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(prf.PrfSet)
      prfs = p.all()
      response = testing_api_pb2.PrfSetKeyIdsResponse()
      response.output.primary_key_id = p.primary_id()
      response.output.key_id.extend(prfs.keys())
      return response
    except tink.TinkError as e:
      return testing_api_pb2.PrfSetKeyIdsResponse(err=str(e))

  def Compute(
      self, request: testing_api_pb2.PrfSetComputeRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.PrfSetComputeResponse:
    """Computes the output of one PRF."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      f = keyset_handle.primitive(prf.PrfSet).all()[request.key_id]
      return testing_api_pb2.PrfSetComputeResponse(
          output=f.compute(request.input_data, request.output_length))
    except tink.TinkError as e:
      return testing_api_pb2.PrfSetComputeResponse(err=str(e))
