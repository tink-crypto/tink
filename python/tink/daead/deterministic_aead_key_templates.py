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

"""Pre-generated KeyTemplate for DeterministicAead.

One can use these templates to generate a new tink_pb2.Keyset with
tink_pb2.KeysetHandle. To generate a new keyset that contains a single
tink_pb2.HmacKey, one can do:
handle = keyset_handle.KeysetHandle(aead_key_templates.AES128_EAX).
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.proto import aes_siv_pb2
from tink.proto import tink_pb2


_AES_SIV_KEY_TYPE_URL = 'type.googleapis.com/google.crypto.tink.AesSivKey'


def create_aes_siv_key_template(key_size: int) -> tink_pb2.KeyTemplate:
  """Creates an AES EAX KeyTemplate, and fills in its values."""
  key_format = aes_siv_pb2.AesSivKeyFormat()
  key_format.key_size = key_size
  key_template = tink_pb2.KeyTemplate()
  key_template.type_url = _AES_SIV_KEY_TYPE_URL
  key_template.output_prefix_type = tink_pb2.TINK
  key_template.value = key_format.SerializeToString()
  return key_template


AES256_SIV = create_aes_siv_key_template(key_size=64)
