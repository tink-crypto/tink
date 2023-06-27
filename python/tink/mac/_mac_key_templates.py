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
"""Pre-generated KeyTemplate for Mac.

One can use these templates to generate a new tink_pb2.Keyset with
tink_pb2.KeysetHandle. To generate a new keyset that contains a single
hmac_pb2.HmacKey, one can do:
handle = keyset_handle.KeysetHandle(mac_key_templates.HMAC_SHA256_128BITTAG).
"""

import warnings

from tink.proto import aes_cmac_pb2
from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import tink_pb2


def _create_hmac_key_template(
    key_size: int, tag_size: int,
    hash_type: common_pb2.HashType) -> tink_pb2.KeyTemplate:
  """Creates a HMAC KeyTemplate, and fills in its values."""
  key_format = hmac_pb2.HmacKeyFormat()
  key_format.params.hash = hash_type
  key_format.params.tag_size = tag_size
  key_format.key_size = key_size
  key_template = tink_pb2.KeyTemplate(
      value=key_format.SerializeToString(),
      type_url='type.googleapis.com/google.crypto.tink.HmacKey',
      output_prefix_type=tink_pb2.TINK,
  )
  return key_template


def _create_aes_cmac_key_template(key_size: int,
                                  tag_size: int) -> tink_pb2.KeyTemplate:
  """"Creates an AES-CMAC KeyTemplate, and fills in its values."""
  key_format = aes_cmac_pb2.AesCmacKeyFormat()
  key_format.key_size = key_size
  key_format.params.tag_size = tag_size
  key_template = tink_pb2.KeyTemplate()
  key_template.value = key_format.SerializeToString()
  key_template.type_url = 'type.googleapis.com/google.crypto.tink.AesCmacKey'
  key_template.output_prefix_type = tink_pb2.TINK
  return key_template


AES_CMAC = _create_aes_cmac_key_template(key_size=32, tag_size=16)
HMAC_SHA256_128BITTAG = _create_hmac_key_template(
    key_size=32, tag_size=16, hash_type=common_pb2.SHA256)
HMAC_SHA256_256BITTAG = _create_hmac_key_template(
    key_size=32, tag_size=32, hash_type=common_pb2.SHA256)
HMAC_SHA512_256BITTAG = _create_hmac_key_template(
    key_size=64, tag_size=32, hash_type=common_pb2.SHA512)
HMAC_SHA512_512BITTAG = _create_hmac_key_template(
    key_size=64, tag_size=64, hash_type=common_pb2.SHA512)


# Deprecated. Use the predefined constant templates above instead.
def create_hmac_key_template(
    key_size: int, tag_size: int,
    hash_type: common_pb2.HashType) -> tink_pb2.KeyTemplate:
  warnings.warn('The "create_hmac_key_template" function is deprecated.',
                DeprecationWarning, 2)
  return _create_hmac_key_template(key_size, tag_size, hash_type)


# Deprecated. Use the predefined constant templates above instead.
def create_aes_cmac_key_template(key_size: int,
                                 tag_size: int) -> tink_pb2.KeyTemplate:
  warnings.warn('The "create_hmac_key_template" function is deprecated.',
                DeprecationWarning, 2)
  return _create_aes_cmac_key_template(key_size, tag_size)
