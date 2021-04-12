# Copyright 2019 Google LLC.
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

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.proto import common_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import tink_pb2
from tink import aead


def create_ecies_aead_hkdf_key_template(
    curve_type: common_pb2.EllipticCurveType,
    ec_point_format: common_pb2.EcPointFormat,
    hash_type: common_pb2.HashType,
    dem_key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyTemplate:
  """Creates a HMAC KeyTemplate, and fills in its values."""
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


ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM = create_ecies_aead_hkdf_key_template(
    curve_type=common_pb2.NIST_P256,
    ec_point_format=common_pb2.UNCOMPRESSED,
    hash_type=common_pb2.SHA256,
    dem_key_template=aead.aead_key_templates.AES128_GCM)

ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM = create_ecies_aead_hkdf_key_template(
    curve_type=common_pb2.NIST_P256,
    ec_point_format=common_pb2.COMPRESSED,
    hash_type=common_pb2.SHA256,
    dem_key_template=aead.aead_key_templates.AES128_GCM)

ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 = (
    create_ecies_aead_hkdf_key_template(
        curve_type=common_pb2.NIST_P256,
        ec_point_format=common_pb2.UNCOMPRESSED,
        hash_type=common_pb2.SHA256,
        dem_key_template=aead.aead_key_templates.AES128_CTR_HMAC_SHA256))

ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 = (
    create_ecies_aead_hkdf_key_template(
        curve_type=common_pb2.NIST_P256,
        ec_point_format=common_pb2.COMPRESSED,
        hash_type=common_pb2.SHA256,
        dem_key_template=aead.aead_key_templates.AES128_CTR_HMAC_SHA256))
