# Copyright 2019 Google LLC
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

"""Pre-generated KeyTemplate for PublicKeySign and PublicKeyVerify.

One can use these templates to generate a new tink_pb2.Keyset with
tink_pb2.KeysetHandle. To generate a new keyset that contains a single
EcdsaPrivateKey, one can do:

handle = keyset_handle.KeysetHandle(signature_key_templates.ECDSA_P256);
"""

import warnings

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import rsa_ssa_pkcs1_pb2
from tink.proto import rsa_ssa_pss_pb2
from tink.proto import tink_pb2
from tink.internal import big_integer_util


_prefix = 'type.googleapis.com/google.crypto.tink.'
_ECDSA_KEY_TYPE_URL = _prefix + 'EcdsaPrivateKey'
_ED25519_KEY_TYPE_URL = _prefix + 'Ed25519PrivateKey'
_RSA_PKCS1_KEY_TYPE_URL = _prefix + 'RsaSsaPkcs1PrivateKey'
_RSA_PSS_KEY_TYPE_URL = _prefix + 'RsaSsaPssPrivateKey'
_RSA_F4 = 65537


def _create_ecdsa_key_template(
    hash_type: common_pb2.HashType,
    curve: common_pb2.EllipticCurveType,
    encoding: ecdsa_pb2.EcdsaSignatureEncoding,
    output_prefix_type: tink_pb2.OutputPrefixType = tink_pb2.TINK
) -> tink_pb2.KeyTemplate:
  """Creates a KeyTemplate containing an EcdsaKeyFormat."""
  params = ecdsa_pb2.EcdsaParams(
      hash_type=hash_type, curve=curve, encoding=encoding)
  key_format = ecdsa_pb2.EcdsaKeyFormat(params=params)
  key_template = tink_pb2.KeyTemplate(
      value=key_format.SerializeToString(),
      type_url=_ECDSA_KEY_TYPE_URL,
      output_prefix_type=output_prefix_type)

  return key_template


def _create_rsa_ssa_pkcs1_key_template(
    hash_type: common_pb2.HashType, modulus_size: int,
    public_exponent: int) -> tink_pb2.KeyTemplate:
  """Creates a KeyTemplate containing an RsaSsaPkcs1KeyFormat."""
  params = rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(hash_type=hash_type)
  key_format = rsa_ssa_pkcs1_pb2.RsaSsaPkcs1KeyFormat(
      params=params,
      modulus_size_in_bits=modulus_size,
      public_exponent=big_integer_util.num_to_bytes(public_exponent))
  key_template = tink_pb2.KeyTemplate(
      value=key_format.SerializeToString(),
      type_url=_RSA_PKCS1_KEY_TYPE_URL,
      output_prefix_type=tink_pb2.TINK)

  return key_template


def _create_rsa_ssa_pss_key_template(
    sig_hash: common_pb2.HashType, mgf1_hash: common_pb2.HashType,
    salt_length: int, modulus_size: int,
    public_exponent: int) -> tink_pb2.KeyTemplate:
  """Creates a KeyTemplate containing an RsaSsaPssKeyFormat."""
  params = rsa_ssa_pss_pb2.RsaSsaPssParams(
      sig_hash=sig_hash, mgf1_hash=mgf1_hash, salt_length=salt_length)
  key_format = rsa_ssa_pss_pb2.RsaSsaPssKeyFormat(
      params=params,
      modulus_size_in_bits=modulus_size,
      public_exponent=big_integer_util.num_to_bytes(public_exponent))
  key_template = tink_pb2.KeyTemplate(
      value=key_format.SerializeToString(),
      type_url=_RSA_PSS_KEY_TYPE_URL,
      output_prefix_type=tink_pb2.TINK)

  return key_template


ECDSA_P256 = _create_ecdsa_key_template(common_pb2.SHA256, common_pb2.NIST_P256,
                                        ecdsa_pb2.DER)
ECDSA_P256_RAW = _create_ecdsa_key_template(common_pb2.SHA256,
                                            common_pb2.NIST_P256,
                                            ecdsa_pb2.IEEE_P1363, tink_pb2.RAW)
# Don't use this template, because it's name is confusing.
# Use ECDSA_P384_SHA512 instead, which is the same template.
ECDSA_P384 = _create_ecdsa_key_template(common_pb2.SHA512, common_pb2.NIST_P384,
                                        ecdsa_pb2.DER)
ECDSA_P384_SHA384 = _create_ecdsa_key_template(common_pb2.SHA384,
                                               common_pb2.NIST_P384,
                                               ecdsa_pb2.DER)
ECDSA_P384_SHA512 = _create_ecdsa_key_template(common_pb2.SHA512,
                                               common_pb2.NIST_P384,
                                               ecdsa_pb2.DER)
ECDSA_P521 = _create_ecdsa_key_template(common_pb2.SHA512, common_pb2.NIST_P521,
                                        ecdsa_pb2.DER)

# Deprecated. This key template does not make sense because IEEE P1363 mandates
# a raw signature.
ECDSA_P256_IEEE_P1363 = _create_ecdsa_key_template(common_pb2.SHA256,
                                                   common_pb2.NIST_P256,
                                                   ecdsa_pb2.IEEE_P1363)
# Deprecated. This key template does not make sense because IEEE P1363 mandates
# a raw signature.
ECDSA_P384_IEEE_P1363 = _create_ecdsa_key_template(common_pb2.SHA512,
                                                   common_pb2.NIST_P384,
                                                   ecdsa_pb2.IEEE_P1363)
# Deprecated. This key template does not make sense because IEEE P1363 mandates
# a raw signature.
ECDSA_P384_SHA384_IEEE_P1363 = _create_ecdsa_key_template(
    common_pb2.SHA384, common_pb2.NIST_P384, ecdsa_pb2.IEEE_P1363)
# Deprecated. This key template does not make sense because IEEE P1363 mandates
# a raw signature.
ECDSA_P521_IEEE_P1363 = _create_ecdsa_key_template(common_pb2.SHA512,
                                                   common_pb2.NIST_P521,
                                                   ecdsa_pb2.IEEE_P1363)

ED25519 = tink_pb2.KeyTemplate(
    type_url=_ED25519_KEY_TYPE_URL, output_prefix_type=tink_pb2.TINK)

RSA_SSA_PKCS1_3072_SHA256_F4 = _create_rsa_ssa_pkcs1_key_template(
    common_pb2.SHA256, 3072, _RSA_F4)
RSA_SSA_PKCS1_4096_SHA512_F4 = _create_rsa_ssa_pkcs1_key_template(
    common_pb2.SHA512, 4096, _RSA_F4)

RSA_SSA_PSS_3072_SHA256_SHA256_32_F4 = _create_rsa_ssa_pss_key_template(
    common_pb2.SHA256, common_pb2.SHA256, 32, 3072, _RSA_F4)
RSA_SSA_PSS_4096_SHA512_SHA512_64_F4 = _create_rsa_ssa_pss_key_template(
    common_pb2.SHA512, common_pb2.SHA512, 64, 4096, _RSA_F4)


# Deprecated. Use the predefined constant templates above instead.
def create_ecdsa_key_template(
    hash_type: common_pb2.HashType,
    curve: common_pb2.EllipticCurveType,
    encoding: ecdsa_pb2.EcdsaSignatureEncoding,
    output_prefix_type: tink_pb2.OutputPrefixType = tink_pb2.TINK
) -> tink_pb2.KeyTemplate:
  warnings.warn('The "create_ecdsa_key_template" function is deprecated.',
                DeprecationWarning, 2)
  return _create_ecdsa_key_template(hash_type, curve, encoding,
                                    output_prefix_type)


# Deprecated. Use the predefined constant templates above instead.
def create_rsa_ssa_pkcs1_key_template(
    hash_type: common_pb2.HashType, modulus_size: int,
    public_exponent: int) -> tink_pb2.KeyTemplate:
  warnings.warn(
      'The "create_rsa_ssa_pkcs1_key_template" function is deprecated.',
      DeprecationWarning, 2)
  return _create_rsa_ssa_pkcs1_key_template(hash_type, modulus_size,
                                            public_exponent)


# Deprecated. Use the predefined constant templates above instead.
def create_rsa_ssa_pss_key_template(
    sig_hash: common_pb2.HashType, mgf1_hash: common_pb2.HashType,
    salt_length: int, modulus_size: int,
    public_exponent: int) -> tink_pb2.KeyTemplate:
  warnings.warn('The "create_rsa_ssa_pss_key_template" function is deprecated.',
                DeprecationWarning, 2)
  return _create_rsa_ssa_pss_key_template(sig_hash, mgf1_hash, salt_length,
                                          modulus_size, public_exponent)
