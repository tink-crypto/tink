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
"""A basic example for using the signature API."""
# [START signature-basic-example]
import tink
from tink import cleartext_keyset_handle
from tink import signature


def example():
  """Sign and verify using digital signatures."""
  # Register the signature key managers. This is needed to create
  # PublicKeySign and PublicKeyVerify primitives later.
  signature.register()

  # A private keyset created with
  # "tinkey create-keyset --key-template=ECDSA_P256 --out private_keyset.cfg".
  # Note that this keyset has the secret key information in cleartext.
  private_keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "ASYMMETRIC_PRIVATE",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
              "value":
                  "EkwSBggDEAIYAhogEiSZ9u2nDtvZuDgWgGsVTIZ5/V08N4ycUspTX0RYRrkiIHpEwHxQd1bImkyMvV2bqtUbgMh5uPSTdnUEGrPXdt56GiEA3iUi+CRN71qy0fOCK66xAW/IvFyjOGtxjppRhSFUneo="
          },
          "keyId": 611814836,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 611814836
  }"""

  # The corresponding public keyset created with
  # "tinkey create-public-keyset --in private_keyset.cfg"
  public_keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "ASYMMETRIC_PUBLIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
              "value":
                  "EgYIAxACGAIaIBIkmfbtpw7b2bg4FoBrFUyGef1dPDeMnFLKU19EWEa5IiB6RMB8UHdWyJpMjL1dm6rVG4DIebj0k3Z1BBqz13beeg=="
          },
          "keyId": 611814836,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 611814836
  }"""

  # Create a keyset handle from the cleartext keyset in the previous
  # step. The keyset handle provides abstract access to the underlying keyset to
  # limit the exposure of accessing the raw key material. WARNING: In practice
  # it is unlikely you will want to use a cleartext_keyset_handle, as it implies
  # that your key material is passed in cleartext which is a security risk.
  private_keyset_handle = cleartext_keyset_handle.read(
      tink.JsonKeysetReader(private_keyset))

  # Retrieve the PublicKeySign primitive we want to use from the keyset
  # handle.
  sign_primitive = private_keyset_handle.primitive(signature.PublicKeySign)

  # Use the primitive to sign a message. In this case the primary key of the
  # keyset will be used (which is also the only key in this example).
  sig = sign_primitive.sign(b'msg')

  # Create a keyset handle from the keyset containing the public key. Note that
  # we could have also created `kh_public` directly using
  # `kh_priv.public_keyset_handle()`.
  public_keyset_handle = cleartext_keyset_handle.read(
      tink.JsonKeysetReader(public_keyset))

  # Retrieve the PublicKeyVerify primitive we want to use from the keyset
  # handle.
  verify_primitive = public_keyset_handle.primitive(signature.PublicKeyVerify)

  # Use the primitive to verify that `sig` is valid signature for the message.
  # Verify finds the correct key in the keyset. If no key is found or
  # verification fails, it raises an error.
  verify_primitive.verify(sig, b'msg')
  # [end signature-basic-example]
