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
"""Pre-generated KeyTemplates for StreamingAead.


Currently, these templates cannot be used to generate keysets, but they can be
used to generate individual keys.
In the future, it will be possible to use these templates to generate a new
tink_pb2.Keyset with tink_pb2.KeysetHandle. To generate a new keyset that
contains a single aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey, one can do:
handle = keyset_handle.KeysetHandle(
  streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB).
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.proto import aes_ctr_hmac_streaming_pb2
from tink.proto import aes_gcm_hkdf_streaming_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2

_AES_GCM_HKDF_STREAMING_KEY_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey')
_AES_CTR_HMAC_STREAMING_KEY_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey')
SEGMENT_SIZE_1MB = 1024 * 1024
SEGMENT_SIZE_4KB = 4 * 1024


def create_aes_gcm_hkdf_streaming_key_template(
    aes_key_size: int, hash_type: common_pb2.HashType, derived_key_size: int,
    ciphertext_segment_size: int) -> tink_pb2.KeyTemplate:
  """Creates an AES GCM HKDF Streaming KeyTemplate, and fills in its values."""
  key_format = aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKeyFormat()
  key_format.key_size = aes_key_size
  key_format.params.hkdf_hash_type = hash_type
  key_format.params.derived_key_size = derived_key_size
  key_format.params.ciphertext_segment_size = ciphertext_segment_size

  key_template = tink_pb2.KeyTemplate()
  key_template.value = key_format.SerializeToString()
  key_template.type_url = _AES_GCM_HKDF_STREAMING_KEY_TYPE_URL
  key_template.output_prefix_type = tink_pb2.RAW
  return key_template


def create_aes_ctr_hmac_streaming_key_template(
    aes_key_size: int, hkdf_hash_type: common_pb2.HashType,
    derived_key_size: int, mac_hash_type: common_pb2.HashType, tag_size: int,
    ciphertext_segment_size: int) -> tink_pb2.KeyTemplate:
  """Creates an AES CTR HMAC Streaming KeyTemplate, and fills in its values."""
  key_format = aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKeyFormat()
  key_format.key_size = aes_key_size

  key_format.params.ciphertext_segment_size = ciphertext_segment_size
  key_format.params.derived_key_size = derived_key_size
  key_format.params.hkdf_hash_type = hkdf_hash_type

  key_format.params.hmac_params.hash = mac_hash_type
  key_format.params.hmac_params.tag_size = tag_size

  key_template = tink_pb2.KeyTemplate()
  key_template.value = key_format.SerializeToString()
  key_template.type_url = _AES_CTR_HMAC_STREAMING_KEY_TYPE_URL
  key_template.output_prefix_type = tink_pb2.RAW
  return key_template


AES128_GCM_HKDF_4KB = create_aes_gcm_hkdf_streaming_key_template(
    aes_key_size=16,
    hash_type=common_pb2.HashType.SHA256,
    derived_key_size=16,
    ciphertext_segment_size=SEGMENT_SIZE_4KB)

AES128_GCM_HKDF_1MB = create_aes_gcm_hkdf_streaming_key_template(
    aes_key_size=16,
    hash_type=common_pb2.HashType.SHA256,
    derived_key_size=16,
    ciphertext_segment_size=SEGMENT_SIZE_1MB)

AES256_GCM_HKDF_4KB = create_aes_gcm_hkdf_streaming_key_template(
    aes_key_size=32,
    hash_type=common_pb2.HashType.SHA256,
    derived_key_size=32,
    ciphertext_segment_size=SEGMENT_SIZE_4KB)

AES256_GCM_HKDF_1MB = create_aes_gcm_hkdf_streaming_key_template(
    aes_key_size=32,
    hash_type=common_pb2.HashType.SHA256,
    derived_key_size=32,
    ciphertext_segment_size=SEGMENT_SIZE_1MB)

AES128_CTR_HMAC_SHA256_4KB = create_aes_ctr_hmac_streaming_key_template(
    aes_key_size=16,
    hkdf_hash_type=common_pb2.HashType.SHA256,
    derived_key_size=16,
    mac_hash_type=common_pb2.HashType.SHA256,
    tag_size=32,
    ciphertext_segment_size=SEGMENT_SIZE_4KB)

AES128_CTR_HMAC_SHA256_1MB = create_aes_ctr_hmac_streaming_key_template(
    aes_key_size=16,
    hkdf_hash_type=common_pb2.HashType.SHA256,
    derived_key_size=16,
    mac_hash_type=common_pb2.HashType.SHA256,
    tag_size=32,
    ciphertext_segment_size=SEGMENT_SIZE_1MB)

AES256_CTR_HMAC_SHA256_4KB = create_aes_ctr_hmac_streaming_key_template(
    aes_key_size=32,
    hkdf_hash_type=common_pb2.HashType.SHA256,
    derived_key_size=32,
    mac_hash_type=common_pb2.HashType.SHA256,
    tag_size=32,
    ciphertext_segment_size=SEGMENT_SIZE_4KB)

AES256_CTR_HMAC_SHA256_1MB = create_aes_ctr_hmac_streaming_key_template(
    aes_key_size=32,
    hkdf_hash_type=common_pb2.HashType.SHA256,
    derived_key_size=32,
    mac_hash_type=common_pb2.HashType.SHA256,
    tag_size=32,
    ciphertext_segment_size=SEGMENT_SIZE_1MB)

