# Copyright 2023 Google LLC
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
# [START mac-basic-example]
import tink
from tink import mac
from tink import secret_key_access


def example():
  """Compute and verify MAC tags."""
  # Register the MAC key managers. This is needed to create a Mac primitive
  # later.
  mac.register()

  # Created with "tinkey create-keyset --key-template=HMAC_SHA256_128BITTAG".
  # Note that this keyset has the secret key information in cleartext.
  keyset = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "SYMMETRIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.HmacKey",
              "value":
                  "EgQIAxAQGiA0LQjovcydWhVQV3k8W9ZSRkd7Ei4Y/TRWApE8guwV4Q=="
          },
          "keyId": 1892702217,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 1892702217
  }"""

  # Create a keyset handle from the cleartext keyset in the previous
  # step. The keyset handle provides abstract access to the underlying keyset to
  # limit access of the raw key material. WARNING: In practice, it is unlikely
  # you will want to use tink.json_proto_keyset_format.parse, as it implies that
  # your key material is passed in cleartext, which is a security risk.
  keyset_handle = tink.json_proto_keyset_format.parse(
      keyset, secret_key_access.TOKEN
  )

  # Retrieve the Mac primitive we want to use from the keyset handle.
  primitive = keyset_handle.primitive(mac.Mac)

  # Use the primitive to compute the MAC for a message. In this case the primary
  # key of the keyset will be used (which is also the only key in this example).
  data = b'data'
  tag = primitive.compute_mac(data)

  # Use the primitive to verify the MAC for the message. Verify finds the
  # correct key in the keyset and verifies the MAC. If no key is found or
  # verification fails, it raises an error.
  primitive.verify_mac(tag, data)
  # [END mac-basic-example]
