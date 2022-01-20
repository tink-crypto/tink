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

import io

import grpc
import tink
from tink import aead
from tink import cleartext_keyset_handle
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead
from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc
from tink.testing import bytes_io


# All KeyTemplate (as Protobuf) defined in the Python API.
_KEY_TEMPLATE = {
    'AES128_EAX':
        aead.aead_key_templates.AES128_EAX,
    'AES128_EAX_RAW':
        aead.aead_key_templates.AES128_EAX_RAW,
    'AES256_EAX':
        aead.aead_key_templates.AES256_EAX,
    'AES256_EAX_RAW':
        aead.aead_key_templates.AES256_EAX_RAW,
    'AES128_GCM':
        aead.aead_key_templates.AES128_GCM,
    'AES128_GCM_RAW':
        aead.aead_key_templates.AES128_GCM_RAW,
    'AES256_GCM':
        aead.aead_key_templates.AES256_GCM,
    'AES256_GCM_RAW':
        aead.aead_key_templates.AES256_GCM_RAW,
    'AES128_GCM_SIV':
        aead.aead_key_templates.AES128_GCM_SIV,
    'AES128_GCM_SIV_RAW':
        aead.aead_key_templates.AES128_GCM_SIV_RAW,
    'AES256_GCM_SIV':
        aead.aead_key_templates.AES256_GCM_SIV,
    'AES256_GCM_SIV_RAW':
        aead.aead_key_templates.AES256_GCM_SIV_RAW,
    'AES128_CTR_HMAC_SHA256':
        aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
    'AES128_CTR_HMAC_SHA256_RAW':
        aead.aead_key_templates.AES128_CTR_HMAC_SHA256_RAW,
    'AES256_CTR_HMAC_SHA256':
        aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
    'AES256_CTR_HMAC_SHA256_RAW':
        aead.aead_key_templates.AES256_CTR_HMAC_SHA256_RAW,
    'XCHACHA20_POLY1305':
        aead.aead_key_templates.XCHACHA20_POLY1305,
    'XCHACHA20_POLY1305_RAW':
        aead.aead_key_templates.XCHACHA20_POLY1305_RAW,
    'AES256_SIV':
        daead.deterministic_aead_key_templates.AES256_SIV,
    'AES128_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB,
    'AES128_CTR_HMAC_SHA256_1MB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB,
    'AES256_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB,
    'AES256_CTR_HMAC_SHA256_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_1MB,
    'AES128_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB,
    'AES128_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_1MB,
    'AES256_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB,
    'AES256_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates
        .ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
    'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
    'AES_CMAC':
        mac.mac_key_templates.AES_CMAC,
    'HMAC_SHA256_128BITTAG':
        mac.mac_key_templates.HMAC_SHA256_128BITTAG,
    'HMAC_SHA256_256BITTAG':
        mac.mac_key_templates.HMAC_SHA256_256BITTAG,
    'HMAC_SHA512_256BITTAG':
        mac.mac_key_templates.HMAC_SHA512_256BITTAG,
    'HMAC_SHA512_512BITTAG':
        mac.mac_key_templates.HMAC_SHA512_512BITTAG,
    'ECDSA_P256':
        signature.signature_key_templates.ECDSA_P256,
    'ECDSA_P256_RAW':
        signature.signature_key_templates.ECDSA_P256_RAW,
    'ECDSA_P384':
        signature.signature_key_templates.ECDSA_P384,
    'ECDSA_P384_SHA384':
        signature.signature_key_templates.ECDSA_P384_SHA384,
    'ECDSA_P384_SHA512':
        signature.signature_key_templates.ECDSA_P384_SHA512,
    'ECDSA_P521':
        signature.signature_key_templates.ECDSA_P521,
    'ECDSA_P256_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P256_IEEE_P1363,
    'ECDSA_P384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_IEEE_P1363,
    'ECDSA_P384_SHA384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_SHA384_IEEE_P1363,
    'ECDSA_P521_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P521_IEEE_P1363,
    'ED25519':
        signature.signature_key_templates.ED25519,
    'RSA_SSA_PKCS1_3072_SHA256_F4':
        signature.signature_key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
    'RSA_SSA_PKCS1_4096_SHA512_F4':
        signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4,
    'RSA_SSA_PSS_3072_SHA256_SHA256_32_F4':
        signature.signature_key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
    'RSA_SSA_PSS_4096_SHA512_SHA512_64_F4':
        signature.signature_key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
    'AES_CMAC_PRF':
        prf.prf_key_templates.AES_CMAC,
    'HMAC_SHA256_PRF':
        prf.prf_key_templates.HMAC_SHA256,
    'HMAC_SHA512_PRF':
        prf.prf_key_templates.HMAC_SHA512,
    'HKDF_SHA256':
        prf.prf_key_templates.HKDF_SHA256,
    'JWT_HS256':
        jwt.jwt_hs256_template(),
    'JWT_HS256_RAW':
        jwt.raw_jwt_hs256_template(),
    'JWT_HS384':
        jwt.jwt_hs384_template(),
    'JWT_HS384_RAW':
        jwt.raw_jwt_hs384_template(),
    'JWT_HS512':
        jwt.jwt_hs512_template(),
    'JWT_HS512_RAW':
        jwt.raw_jwt_hs512_template(),
    'JWT_ES256':
        jwt.jwt_es256_template(),
    'JWT_ES256_RAW':
        jwt.raw_jwt_es256_template(),
    'JWT_ES384':
        jwt.jwt_es384_template(),
    'JWT_ES384_RAW':
        jwt.raw_jwt_es384_template(),
    'JWT_ES512':
        jwt.jwt_es512_template(),
    'JWT_ES512_RAW':
        jwt.raw_jwt_es512_template(),
    'JWT_RS256_2048_F4':
        jwt.jwt_rs256_2048_f4_template(),
    'JWT_RS256_2048_F4_RAW':
        jwt.raw_jwt_rs256_2048_f4_template(),
    'JWT_RS256_3072_F4':
        jwt.jwt_rs256_3072_f4_template(),
    'JWT_RS256_3072_F4_RAW':
        jwt.raw_jwt_rs256_3072_f4_template(),
    'JWT_RS384_3072_F4':
        jwt.jwt_rs384_3072_f4_template(),
    'JWT_RS384_3072_F4_RAW':
        jwt.raw_jwt_rs384_3072_f4_template(),
    'JWT_RS512_4096_F4':
        jwt.jwt_rs512_4096_f4_template(),
    'JWT_RS512_4096_F4_RAW':
        jwt.raw_jwt_rs512_4096_f4_template(),
    'JWT_PS256_2048_F4':
        jwt.jwt_ps256_2048_f4_template(),
    'JWT_PS256_2048_F4_RAW':
        jwt.raw_jwt_ps256_2048_f4_template(),
    'JWT_PS256_3072_F4':
        jwt.jwt_ps256_3072_f4_template(),
    'JWT_PS256_3072_F4_RAW':
        jwt.raw_jwt_ps256_3072_f4_template(),
    'JWT_PS384_3072_F4':
        jwt.jwt_ps384_3072_f4_template(),
    'JWT_PS384_3072_F4_RAW':
        jwt.raw_jwt_ps384_3072_f4_template(),
    'JWT_PS512_4096_F4':
        jwt.jwt_ps512_4096_f4_template(),
    'JWT_PS512_4096_F4_RAW':
        jwt.raw_jwt_ps512_4096_f4_template(),
}


class MetadataServicer(testing_api_pb2_grpc.MetadataServicer):
  """A service with metadata about the server."""

  def GetServerInfo(
      self, request: testing_api_pb2.ServerInfoRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.ServerInfoResponse:
    """Returns information about the server."""
    return testing_api_pb2.ServerInfoResponse(language='python')


class KeysetServicer(testing_api_pb2_grpc.KeysetServicer):
  """A service for testing Keyset operations."""

  def GetTemplate(
      self, request: testing_api_pb2.KeysetTemplateRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.KeysetTemplateResponse:
    """Returns the key template for the given template name."""
    if request.template_name not in _KEY_TEMPLATE:
      return testing_api_pb2.KeysetTemplateResponse(
          err='template %s not found' % request.template_name)
    return  testing_api_pb2.KeysetTemplateResponse(
        key_template=_KEY_TEMPLATE[request.template_name].SerializeToString())

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

  def ReadEncrypted(
      self, request: testing_api_pb2.KeysetReadEncryptedRequest,
      context: grpc.ServicerContext
  ) -> testing_api_pb2.KeysetReadEncryptedResponse:
    """Reads an encrypted keyset."""
    try:
      master_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.master_keyset))
      master_aead = master_keyset_handle.primitive(aead.Aead)

      reader = tink.BinaryKeysetReader(request.encrypted_keyset)
      if request.HasField('associated_data'):
        keyset_handle = tink.read_keyset_handle_with_associated_data(
            reader, master_aead, request.associated_data.value)
      else:
        keyset_handle = tink.read_keyset_handle(reader, master_aead)

      keyset = io.BytesIO()
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(keyset), keyset_handle)
      return testing_api_pb2.KeysetReadEncryptedResponse(
          keyset=keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetReadEncryptedResponse(err=str(e))

  def WriteEncrypted(
      self, request: testing_api_pb2.KeysetWriteEncryptedRequest,
      context: grpc.ServicerContext
  ) -> testing_api_pb2.KeysetWriteEncryptedResponse:
    """Writes an encrypted keyset."""
    try:
      master_keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.master_keyset))
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      master_aead = master_keyset_handle.primitive(aead.Aead)

      encrypted_keyset = io.BytesIO()
      if request.HasField('associated_data'):
        keyset_handle.write_with_associated_data(
            tink.BinaryKeysetWriter(encrypted_keyset), master_aead,
            request.associated_data.value)
      else:
        keyset_handle.write(
            tink.BinaryKeysetWriter(encrypted_keyset), master_aead)
      return testing_api_pb2.KeysetWriteEncryptedResponse(
          encrypted_keyset=encrypted_keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetWriteEncryptedResponse(err=str(e))


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
