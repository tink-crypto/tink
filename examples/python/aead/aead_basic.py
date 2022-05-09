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
"""A minimal example for using the AEAD API."""
# [START aead-basic-example]
import tink
from tink import aead
from tink import cleartext_keyset_handle


def example():
  """Encrypt and decrypt using AEAD."""
  # Register the AEAD key managers. This is needed to create an Aead primitive
  # later.
  aead.register()

  # A keyset created with "tinkey create-keyset --key-template=AES256_GCM". Note
  # that this keyset has the secret key information in cleartext.
  keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "SYMMETRIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.AesGcmKey",
              "value":
                  "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "keyId": 294406504,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 294406504
  }"""

  # Create a keyset handle from the cleartext keyset in the previous
  # step. The keyset handle provides abstract access to the underlying keyset to
  # limit the exposure of accessing the raw key material. WARNING: In practice
  # it is unlikely you will want to use a cleartext_keyset_handle, as it implies
  # that your key material is passed in cleartext which is a security risk.
  keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(keyset))

  # Retrieve the Aead primitive we want to use from the keyset handle.
  primitive = keyset_handle.primitive(aead.Aead)

  # Use the primitive to encrypt a message. In this case the primary key of the
  # keyset will be used (which is also the only key in this example).
  ciphertext = primitive.encrypt(b'msg', b'associated_data')

  # Use the primitive to decrypt the message. Decrypt finds the correct key in
  # the keyset and decrypts the ciphertext. If no key is found or decryption
  # fails, it raises an error.
  output = primitive.decrypt(ciphertext, b'associated_data')
  # [end aead-basic-example]
  assert output == b'msg'
