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
"""A basic example for using the hybrid encryption API."""
# [START hybrid-basic-example]
import tink
from tink import cleartext_keyset_handle
from tink import hybrid


def example():
  """Encrypt and decrypt using hybrid encryption."""
  # Register the hybrid encryption key managers. This is needed to create
  # HybridEncrypt and HybridDecrypt primitives later.
  hybrid.register()

  # A private keyset created with
  # tinkey create-keyset \
  #   --key-template=DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM \
  #   --out private_keyset.cfg
  # Note that this keyset has the secret key information in cleartext.
  private_keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "ASYMMETRIC_PRIVATE",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
              "value":
                  "EioSBggBEAEYAhogVWQpmQoz74jcAp5WOD36KiBQ71MVCpn2iWfOzWLtKV4aINfn8qlMbyijNJcCzrafjsgJ493ZZGN256KTfKw0WN+p"
          },
          "keyId": 958452012,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 958452012
  }"""

  # The corresponding public keyset created with
  # "tinkey create-public-keyset --in private_keyset.cfg"
  public_keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "ASYMMETRIC_PUBLIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.HpkePublicKey",
              "value":
                  "EgYIARABGAIaIFVkKZkKM++I3AKeVjg9+iogUO9TFQqZ9olnzs1i7Sle"          },
          "keyId": 958452012,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 958452012
  }"""

  # Create a keyset handle from the keyset containing the public key. Because
  # this keyset does not contain any secrets, we can use
  # `tink.read_no_secret_keyset_handle`.
  public_keyset_handle = tink.read_no_secret_keyset_handle(
      tink.JsonKeysetReader(public_keyset))

  # Retrieve the HybridEncrypt primitive from the keyset handle.
  enc_primitive = public_keyset_handle.primitive(hybrid.HybridEncrypt)

  # Use enc_primitive to encrypt a message. In this case the primary key of the
  # keyset will be used (which is also the only key in this example).
  ciphertext = enc_primitive.encrypt(b'message', b'context_info')

  # Create a keyset handle from the private keyset. The keyset handle provides
  # abstract access to the underlying keyset to limit the exposure of accessing
  # the raw key material. WARNING: In practice, it is unlikely you will want to
  # use a cleartext_keyset_handle, as it implies that your key material is
  # passed in cleartext which is a security risk.
  private_keyset_handle = cleartext_keyset_handle.read(
      tink.JsonKeysetReader(private_keyset)
  )

  # Retrieve the HybridDecrypt primitive from the private keyset handle.
  dec_primitive = private_keyset_handle.primitive(hybrid.HybridDecrypt)

  # Use dec_primitive to decrypt the message. Decrypt finds the correct key in
  # the keyset and decrypts the ciphertext. If no key is found or decryption
  # fails, it raises an error.
  decrypted = dec_primitive.decrypt(ciphertext, b'context_info')
  # [END hybrid-basic-example]
  assert decrypted == b'message'
