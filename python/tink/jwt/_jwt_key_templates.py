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
"""Pre-generated JWT KeyTemplate."""

from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import jwt_rsa_ssa_pkcs1_pb2
from tink.proto import jwt_rsa_ssa_pss_pb2
from tink.proto import tink_pb2


_F4 = 65537

# TODO(juerg): Add TINK key templates.


def _create_jwt_hmac_template(
    algorithm: jwt_hmac_pb2.JwtHmacAlgorithm, key_size: int,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  key_format = jwt_hmac_pb2.JwtHmacKeyFormat(
      algorithm=algorithm, key_size=key_size)
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type)


def _create_jwt_ecdsa_template(
    algorithm: jwt_ecdsa_pb2.JwtEcdsaAlgorithm,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  key_format = jwt_ecdsa_pb2.JwtEcdsaKeyFormat(
      algorithm=algorithm)
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type)


# TODO(juerg): Move this function into a util lib.
def _num_to_bytes(n: int) -> bytes:
  """Converts a number to bytes."""
  if n < 0:
    raise OverflowError("number can't be negative")
  if n == 0:
    return b'\x00'
  octets = bytearray()
  while n:
    octets.append(n % 256)
    n //= 256
  return bytes(octets[::-1])


def _create_jwt_rsa_ssa_pkcs1_template(
    algorithm: jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1Algorithm, modulus_size: int,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  key_format = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1KeyFormat(
      algorithm=algorithm,
      modulus_size_in_bits=modulus_size,
      public_exponent=_num_to_bytes(_F4))
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type)


def _create_jwt_rsa_ssa_pss_template(
    algorithm: jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssAlgorithm, modulus_size: int,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  key_format = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssKeyFormat(
      algorithm=algorithm,
      modulus_size_in_bits=modulus_size,
      public_exponent=_num_to_bytes(_F4))
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type)


# Hmac Templates
def jwt_hs256_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS256, 32, tink_pb2.TINK)


def raw_jwt_hs256_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS256, 32, tink_pb2.RAW)


def jwt_hs384_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS384, 48, tink_pb2.TINK)


def raw_jwt_hs384_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS384, 48, tink_pb2.RAW)


def jwt_hs512_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS512, 64, tink_pb2.TINK)


def raw_jwt_hs512_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS512, 64, tink_pb2.RAW)


# ECDSA Templates
def jwt_es256_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES256, tink_pb2.TINK)


def raw_jwt_es256_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES256, tink_pb2.RAW)


def jwt_es384_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES384, tink_pb2.TINK)


def raw_jwt_es384_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES384, tink_pb2.RAW)


def jwt_es512_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES512, tink_pb2.TINK)


def raw_jwt_es512_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES512, tink_pb2.RAW)


# RSA SSA PKCS1 Templates
def jwt_rs256_2048_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS256, 2048,
                                            tink_pb2.TINK)


def raw_jwt_rs256_2048_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS256, 2048,
                                            tink_pb2.RAW)


def jwt_rs256_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS256, 3072,
                                            tink_pb2.TINK)


def raw_jwt_rs256_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS256, 3072,
                                            tink_pb2.RAW)


def jwt_rs384_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS384, 3072,
                                            tink_pb2.TINK)


def raw_jwt_rs384_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS384, 3072,
                                            tink_pb2.RAW)


def jwt_rs512_4096_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS512, 4096,
                                            tink_pb2.TINK)


def raw_jwt_rs512_4096_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pkcs1_template(jwt_rsa_ssa_pkcs1_pb2.RS512, 4096,
                                            tink_pb2.RAW)


# RSA SSA PSS Templates
def jwt_ps256_2048_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS256, 2048,
                                          tink_pb2.TINK)


def raw_jwt_ps256_2048_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS256, 2048,
                                          tink_pb2.RAW)


def jwt_ps256_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS256, 3072,
                                          tink_pb2.TINK)


def raw_jwt_ps256_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS256, 3072,
                                          tink_pb2.RAW)


def jwt_ps384_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS384, 3072,
                                          tink_pb2.TINK)


def raw_jwt_ps384_3072_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS384, 3072,
                                          tink_pb2.RAW)


def jwt_ps512_4096_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS512, 4096,
                                          tink_pb2.TINK)


def raw_jwt_ps512_4096_f4_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_rsa_ssa_pss_template(jwt_rsa_ssa_pss_pb2.PS512, 4096,
                                          tink_pb2.RAW)
