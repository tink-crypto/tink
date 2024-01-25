# Copyright 2019 Google LLC
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

"""Tests for tink.python.tink.aead_wrapper."""

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import core
from tink import hybrid
from tink import secret_key_access
from tink.testing import keyset_builder


TEMPLATE = hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
RAW_TEMPLATE = keyset_builder.raw_template(TEMPLATE)

PRIVATE_KEYSET_WITH_PRIMARY = """
  {
    "primaryKeyId": 2160196527,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
          "value": "GiCP3xXdT0G7GQMQ+k7nsl+W5ElO3EN6ybwSPTGWdArHTBKKASIgrgyjrYI2mV+K8Csa703wGgtlOG+yxHajoM6quNA1IHEaIASUo/ubipc/Vn+WhN64qmnzp9mqzyvQTQ5jrNt6Xwq6EkQYARI6EjgYARICEBAKMHR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkFlc0djbUtleQoEEAMIAg==",
          "keyMaterialType": "ASYMMETRIC_PRIVATE"
        },
        "status": "ENABLED",
        "keyId": 2160196527,
        "outputPrefixType": "TINK"
      }
    ]
  }"""
# Same as PRIVATE_KEYSET_WITH_PRIMARY, but without primaryKeyId.
PRIVATE_KEYSET_WITHOUT_PRIMARY = """
  {
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
          "value": "GiCP3xXdT0G7GQMQ+k7nsl+W5ElO3EN6ybwSPTGWdArHTBKKASIgrgyjrYI2mV+K8Csa703wGgtlOG+yxHajoM6quNA1IHEaIASUo/ubipc/Vn+WhN64qmnzp9mqzyvQTQ5jrNt6Xwq6EkQYARI6EjgYARICEBAKMHR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkFlc0djbUtleQoEEAMIAg==",
          "keyMaterialType": "ASYMMETRIC_PRIVATE"
        },
        "status": "ENABLED",
        "keyId": 2160196527,
        "outputPrefixType": "TINK"
      }
    ]
  }"""
PUBLIC_KEYSET_WITH_PRIMARY = """
  {
    "primaryKeyId": 2160196527,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
          "value": "IiCuDKOtgjaZX4rwKxrvTfAaC2U4b7LEdqOgzqq40DUgcRogBJSj+5uKlz9Wf5aE3riqafOn2arPK9BNDmOs23pfCroSRBgBEjoSOBgBEgIQEAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5CgQQAwgC",
          "keyMaterialType": "ASYMMETRIC_PUBLIC"
        },
        "status": "ENABLED",
        "keyId": 2160196527,
        "outputPrefixType": "TINK"
      }
    ]
  }"""
# Same as PUBLIC_KEYSET_WITH_PRIMARY, but without primaryKeyId.
PUBLIC_KEYSET_WITHOUT_PRIMARY = """
  {
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
          "value": "IiCuDKOtgjaZX4rwKxrvTfAaC2U4b7LEdqOgzqq40DUgcRogBJSj+5uKlz9Wf5aE3riqafOn2arPK9BNDmOs23pfCroSRBgBEjoSOBgBEgIQEAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5CgQQAwgC",
          "keyMaterialType": "ASYMMETRIC_PUBLIC"
        },
        "status": "ENABLED",
        "keyId": 2160196527,
        "outputPrefixType": "TINK"
      }
    ]
  }"""


def setUpModule():
  hybrid.register()


class HybridWrapperTest(parameterized.TestCase):

  @parameterized.parameters([TEMPLATE, RAW_TEMPLATE])
  def test_encrypt_decrypt(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()

    hybrid_enc = public_handle.primitive(hybrid.HybridEncrypt)
    ciphertext = hybrid_enc.encrypt(b'plaintext', b'context')
    hybrid_dec = private_handle.primitive(hybrid.HybridDecrypt)
    self.assertEqual(hybrid_dec.decrypt(ciphertext, b'context'),
                     b'plaintext')

  @parameterized.parameters([TEMPLATE, RAW_TEMPLATE])
  def test_decrypt_unknown_ciphertext_fails(self, template):
    unknown_private_handle = tink.new_keyset_handle(template)
    unknown_public_handle = unknown_private_handle.public_keyset_handle()
    unknown_enc = unknown_public_handle.primitive(hybrid.HybridEncrypt)
    unknown_ciphertext = unknown_enc.encrypt(b'plaintext', b'context')

    private_handle = tink.new_keyset_handle(template)
    hybrid_dec = private_handle.primitive(hybrid.HybridDecrypt)
    with self.assertRaises(core.TinkError):
      hybrid_dec.decrypt(unknown_ciphertext, b'context')

  @parameterized.parameters([TEMPLATE, RAW_TEMPLATE])
  def test_decrypt_wrong_associated_data_fails(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()

    hybrid_enc = public_handle.primitive(hybrid.HybridEncrypt)
    ciphertext = hybrid_enc.encrypt(b'plaintext', b'context')
    hybrid_dec = private_handle.primitive(hybrid.HybridDecrypt)
    with self.assertRaises(core.TinkError):
      hybrid_dec.decrypt(ciphertext, b'wrong_context')

  @parameterized.parameters([(TEMPLATE, TEMPLATE),
                             (RAW_TEMPLATE, TEMPLATE),
                             (TEMPLATE, RAW_TEMPLATE),
                             (RAW_TEMPLATE, RAW_TEMPLATE)])
  def test_encrypt_decrypt_with_key_rotation(self, old_template, new_template):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_template)
    builder.set_primary_key(older_key_id)
    private_handle1 = builder.keyset_handle()
    dec1 = private_handle1.primitive(hybrid.HybridDecrypt)
    enc1 = private_handle1.public_keyset_handle().primitive(
        hybrid.HybridEncrypt)

    newer_key_id = builder.add_new_key(new_template)
    private_handle2 = builder.keyset_handle()
    dec2 = private_handle2.primitive(hybrid.HybridDecrypt)
    enc2 = private_handle2.public_keyset_handle().primitive(
        hybrid.HybridEncrypt)

    builder.set_primary_key(newer_key_id)
    private_handle3 = builder.keyset_handle()
    dec3 = private_handle3.primitive(hybrid.HybridDecrypt)
    enc3 = private_handle3.public_keyset_handle().primitive(
        hybrid.HybridEncrypt)

    builder.disable_key(older_key_id)
    private_handle4 = builder.keyset_handle()
    dec4 = private_handle4.primitive(hybrid.HybridDecrypt)
    enc4 = private_handle4.public_keyset_handle().primitive(
        hybrid.HybridEncrypt)
    self.assertNotEqual(older_key_id, newer_key_id)

    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext1 = enc1.encrypt(b'plaintext', b'context')
    self.assertEqual(dec1.decrypt(ciphertext1, b'context'), b'plaintext')
    self.assertEqual(dec2.decrypt(ciphertext1, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext1, b'context'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec4.decrypt(ciphertext1, b'context')

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext2 = enc2.encrypt(b'plaintext', b'context')
    self.assertEqual(dec1.decrypt(ciphertext2, b'context'), b'plaintext')
    self.assertEqual(dec2.decrypt(ciphertext2, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext2, b'context'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec4.decrypt(ciphertext2, b'context')

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext3 = enc3.encrypt(b'plaintext', b'context')
    with self.assertRaises(tink.TinkError):
      _ = dec1.decrypt(ciphertext3, b'context')
    self.assertEqual(dec2.decrypt(ciphertext3, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext3, b'context'), b'plaintext')
    self.assertEqual(dec4.decrypt(ciphertext3, b'context'), b'plaintext')

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext4 = enc4.encrypt(b'plaintext', b'context')
    with self.assertRaises(tink.TinkError):
      _ = dec1.decrypt(ciphertext4, b'context')
    self.assertEqual(dec2.decrypt(ciphertext4, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext4, b'context'), b'plaintext')
    self.assertEqual(dec4.decrypt(ciphertext4, b'context'), b'plaintext')

  def test_encrypt_decrypt_with_primary_key_succeeds(self):
    private_handle_with_primary = tink.json_proto_keyset_format.parse(
        PRIVATE_KEYSET_WITH_PRIMARY, secret_key_access.TOKEN
    )
    public_handle_with_primary = (
        tink.json_proto_keyset_format.parse_without_secret(
            PUBLIC_KEYSET_WITH_PRIMARY
        )
    )
    dec = private_handle_with_primary.primitive(hybrid.HybridDecrypt)
    enc = public_handle_with_primary.primitive(hybrid.HybridEncrypt)
    ciphertext = enc.encrypt(b'plaintext', b'context')
    self.assertEqual(dec.decrypt(ciphertext, b'context'), b'plaintext')

  def test_encrypt_decrypt_without_primary_key_fails(self):
    with self.assertRaises(tink.TinkError):
      tink.json_proto_keyset_format.parse(
          PRIVATE_KEYSET_WITHOUT_PRIMARY, secret_key_access.TOKEN
      )
    # Currently, the public keyset only fails when 'encrypt' is called.
    # TODO(b/228140127): It would be preferable that it fails earlier.
    public_handle_without_primary = (
        tink.json_proto_keyset_format.parse_without_secret(
            PUBLIC_KEYSET_WITHOUT_PRIMARY
        )
    )
    enc_without_primary = public_handle_without_primary.primitive(
        hybrid.HybridEncrypt)
    with self.assertRaises(tink.TinkError):
      enc_without_primary.encrypt(b'plaintext', b'context')


if __name__ == '__main__':
  absltest.main()
