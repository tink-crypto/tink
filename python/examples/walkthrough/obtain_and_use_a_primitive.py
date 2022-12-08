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
"""Example to showcase how to obtain and use a primitive from a keyset."""
# [START tink_walkthrough_obtain_and_use_a_primitive]
import tink
from tink import aead


def AeadEncrypt(keyset_handle: tink.KeysetHandle, plaintext: bytes,
                associated_data: bytes) -> bytes:
  """AEAD encrypts a plaintext with the primary key in keyset_handle.

  Prerequisites for this example:
   - Register AEAD implementations of Tink.
   - Create a keyset and get a handle to it.

  Args:
    keyset_handle: Keyset handle containing at least an AEAD key.
    plaintext: Plaintext to encrypt.
    associated_data: Associated data.

  Returns:
    The resulting ciphertext

  Raises:
    tink.TinkError in case of errors.
  """
  # To facilitate key rotation, `primitive` returns an Aead primitive that
  # "wraps" multiple Aead primitives in the keyset. It uses the primary key to
  # encrypt; For the key we use in this example, the first 5 bytes of the
  # ciphertext contain the ID of the encryption key.
  aead_primitive = keyset_handle.primitive(aead.Aead)
  return aead_primitive.encrypt(plaintext, associated_data)


def AeadDecrypt(keyset_handle: tink.KeysetHandle, ciphertext: bytes,
                associated_data: bytes) -> bytes:
  """AEAD decrypts a ciphertext with the corresponding key in keyset_handle.

  Prerequisites for this example:
   - Register AEAD implementations of Tink.
   - Create a keyset and get a handle to it.
   - Encrypt a plaintext with an AEAD primitive in keyset_handle.

  Args:
    keyset_handle: Keyset handle containing at least an AEAD key.
    ciphertext: Tink ciphertext to decrypt.
    associated_data: Associated data.

  Returns:
    The resulting ciphertext

  Raises:
    tink.TinkError in case of errors.
  """
  # To facilitate key rotation, `primitive` returns an Aead primitive that
  # "wraps" multiple Aead primitives in the keyset. In this example, it uses the
  # key that was used to encrypt looking it up by key ID; the ID is contained in
  # the first 5 bytes of the ciphertext.
  aead_primitive = keyset_handle.primitive(aead.Aead)
  return aead_primitive.decrypt(ciphertext, associated_data)


# [END tink_walkthrough_obtain_and_use_a_primitive]
