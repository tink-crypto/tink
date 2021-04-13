# Copyright 2020 Google LLC
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

"""Pre-generated KeyTemplate for Aead.

One can use these templates to generate a new tink_pb2.Keyset with
tink_pb2.KeysetHandle. To generate a new keyset that contains a single
aes_eax_pb2.AesEaxKey, one can do:
handle = keyset_handle.KeysetHandle(aead_key_templates.AES128_EAX).
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.proto import aes_cmac_prf_pb2
from tink.proto import common_pb2
from tink.proto import hkdf_prf_pb2
from tink.proto import hmac_prf_pb2
from tink.proto import tink_pb2

_AES_CMAC_PRF_KEY_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.AesCmacPrfKey')
_HMAC_PRF_KEY_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HmacPrfKey'
_HKDF_PRF_KEY_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HkdfPrfKey'


def _create_aes_cmac_key_template(key_size: int) -> tink_pb2.KeyTemplate:
  """Creates an AES CMAC PRF KeyTemplate, and fills in its values."""
  key_format = aes_cmac_prf_pb2.AesCmacPrfKeyFormat()
  key_format.key_size = key_size
  key_format.version = 0
  key_template = tink_pb2.KeyTemplate()
  key_template.value = key_format.SerializeToString()
  key_template.type_url = _AES_CMAC_PRF_KEY_TYPE_URL
  key_template.output_prefix_type = tink_pb2.RAW
  return key_template


def _create_hmac_key_template(
    key_size: int, hash_type: common_pb2.HashType) -> tink_pb2.KeyTemplate:
  """Creates an HMAC PRF KeyTemplate, and fills in its values."""
  key_format = hmac_prf_pb2.HmacPrfKeyFormat()
  key_format.params.hash = hash_type
  key_format.key_size = key_size
  key_format.version = 0
  key_template = tink_pb2.KeyTemplate()
  key_template.value = key_format.SerializeToString()
  key_template.type_url = _HMAC_PRF_KEY_TYPE_URL
  key_template.output_prefix_type = tink_pb2.RAW
  return key_template


def _create_hkdf_key_template(
    key_size: int, hash_type: common_pb2.HashType) -> tink_pb2.KeyTemplate:
  """Creates an HKDF PRF KeyTemplate, and fills in its values."""
  key_format = hkdf_prf_pb2.HkdfPrfKeyFormat()
  key_format.params.hash = hash_type
  key_format.key_size = key_size
  key_format.version = 0
  key_template = tink_pb2.KeyTemplate()
  key_template.value = key_format.SerializeToString()
  key_template.type_url = _HKDF_PRF_KEY_TYPE_URL
  key_template.output_prefix_type = tink_pb2.RAW
  return key_template


AES_CMAC = _create_aes_cmac_key_template(key_size=32)
HMAC_SHA256 = _create_hmac_key_template(
    key_size=32, hash_type=common_pb2.SHA256)
HMAC_SHA512 = _create_hmac_key_template(
    key_size=64, hash_type=common_pb2.SHA512)
HKDF_SHA256 = _create_hkdf_key_template(
    key_size=32, hash_type=common_pb2.SHA256)
