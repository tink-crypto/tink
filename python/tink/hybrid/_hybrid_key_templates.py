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

"""Pre-generated KeyTemplate for HybridEncryption.

One can use these templates to generate a new tink_pb2.Keyset with
tink_pb2.KeysetHandle. To generate a new keyset that contains a single
tink_pb2.HmacKey, one can do:
handle = keyset_handle.KeysetHandle(mac_key_templates.HMAC_SHA256_128BITTAG).
"""

import warnings

from tink.proto import common_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import hpke_pb2
from tink.proto import tink_pb2
from tink import aead


def _create_ecies_aead_hkdf_key_template(
    curve_type: common_pb2.EllipticCurveType,
    ec_point_format: common_pb2.EcPointFormat, hash_type: common_pb2.HashType,
    dem_key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyTemplate:
  """Creates an ECIES-AEAD-HKDF KeyTemplate, and fills in its values."""
  key_format = ecies_aead_hkdf_pb2.EciesAeadHkdfKeyFormat()
  key_format.params.kem_params.curve_type = curve_type
  key_format.params.kem_params.hkdf_hash_type = hash_type
  key_format.params.dem_params.aead_dem.CopyFrom(dem_key_template)
  key_format.params.ec_point_format = ec_point_format

  key_template = tink_pb2.KeyTemplate()
  key_template.type_url = (
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey')
  key_template.value = key_format.SerializeToString()
  key_template.output_prefix_type = tink_pb2.TINK
  return key_template


def _create_hpke_key_template(
    hpke_kem: hpke_pb2.HpkeKem, hpke_kdf: hpke_pb2.HpkeKdf,
    hpke_aead: hpke_pb2.HpkeAead,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  """Creates an HPKE KeyTemplate, and fills in its values."""
  key_format = hpke_pb2.HpkeKeyFormat()
  key_format.params.kem = hpke_kem
  key_format.params.kdf = hpke_kdf
  key_format.params.aead = hpke_aead

  key_template = tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.HpkePrivateKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type,
  )
  return key_template


ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM = _create_ecies_aead_hkdf_key_template(
    curve_type=common_pb2.NIST_P256,
    ec_point_format=common_pb2.UNCOMPRESSED,
    hash_type=common_pb2.SHA256,
    dem_key_template=aead.aead_key_templates.AES128_GCM)

ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM = _create_ecies_aead_hkdf_key_template(
    curve_type=common_pb2.NIST_P256,
    ec_point_format=common_pb2.COMPRESSED,
    hash_type=common_pb2.SHA256,
    dem_key_template=aead.aead_key_templates.AES128_GCM)

ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 = (
    _create_ecies_aead_hkdf_key_template(
        curve_type=common_pb2.NIST_P256,
        ec_point_format=common_pb2.UNCOMPRESSED,
        hash_type=common_pb2.SHA256,
        dem_key_template=aead.aead_key_templates.AES128_CTR_HMAC_SHA256))

ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 = (
    _create_ecies_aead_hkdf_key_template(
        curve_type=common_pb2.NIST_P256,
        ec_point_format=common_pb2.COMPRESSED,
        hash_type=common_pb2.SHA256,
        dem_key_template=aead.aead_key_templates.AES128_CTR_HMAC_SHA256))

DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM = (
    _create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.AES_128_GCM,
        output_prefix_type=tink_pb2.TINK))

DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW = (
    _create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.AES_128_GCM,
        output_prefix_type=tink_pb2.RAW))

DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM = (
    _create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.AES_256_GCM,
        output_prefix_type=tink_pb2.TINK))

DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW = (
    _create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.AES_256_GCM,
        output_prefix_type=tink_pb2.RAW))

DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 = (
    _create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.CHACHA20_POLY1305,
        output_prefix_type=tink_pb2.TINK))

DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW = (
    _create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.CHACHA20_POLY1305,
        output_prefix_type=tink_pb2.RAW))


# Deprecated. Use the predefined constant templates above instead.
def create_ecies_aead_hkdf_key_template(
    curve_type: common_pb2.EllipticCurveType,
    ec_point_format: common_pb2.EcPointFormat, hash_type: common_pb2.HashType,
    dem_key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyTemplate:
  warnings.warn(
      'The "create_ecies_aead_hkdf_key_template" function is deprecated.',
      DeprecationWarning, 2)
  return _create_ecies_aead_hkdf_key_template(curve_type, ec_point_format,
                                              hash_type, dem_key_template)
