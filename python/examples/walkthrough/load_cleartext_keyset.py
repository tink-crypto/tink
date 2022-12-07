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
"""Example to showcase how to load a cleartext keyset."""
# [START tink_walkthrough_load_cleartext_keyset]
import tink

from tink import cleartext_keyset_handle


def LoadKeyset(serialized_keyset: str) -> tink.KeysetHandle:
  r"""Loads a JSON-serialized unencrypted keyset and returns a KeysetHandle.

  Prerequisites for this example:
    - Create an plaintext keyset in JSON, for example, using Tinkey:

      tinkey create-key --key-template AES256_GCM --out-format json \
        --out keyset.json

  Args:
    serialized_keyset: JSON serialized keyset.

  Returns:
    A handle to the loaded keyset.

  Raises:
    tink.TinkError in case of errors.
  """
  return cleartext_keyset_handle.read(tink.JsonKeysetReader(serialized_keyset))


# [END tink_walkthrough_load_cleartext_keyset]
