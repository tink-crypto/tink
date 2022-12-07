# Copyright 2022 Google LLC
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
"""Example to showcase how to create a keyset."""
# [START tink_walkthrough_create_keyset]
import tink
from tink import aead


def CreateAead128GcmKeyset() -> tink.KeysetHandle:
  """Creates a keyset with a single AES128-GCM key and return a handle to it.

  Prerequisites:
    - Register AEAD implementations of Tink.

  Returns:
    A handle to the created keyset.

  Raises:
    tink.TinkError in case of errors.
  """
  # Tink provides pre-baked templetes. For example, we generate a key template
  # for AES128-GCM.
  key_template = aead.aead_key_templates.AES128_GCM
  # This will generate a new keyset with only *one* key and return a keyset
  # handle to it.
  return tink.new_keyset_handle(key_template)


# [END tink_walkthrough_create_keyset]
