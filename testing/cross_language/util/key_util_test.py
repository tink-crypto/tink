# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License")
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
"""Tests for tink.testing.cross_language.util.key_util."""

from absl.testing import absltest
from absl.testing import parameterized

from google.protobuf import text_format
from tink.proto import tink_pb2
from util import key_util

KEY_TEMPLATE_1 = r"""
 type_url: "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"
 value: "\n@\022>\022<\n0type.googleapis.com/google.crypto.tink.AesEaxKey\022\006\n\002\010\020\020\020\030\001"
 output_prefix_type: RAW
"""

# The same template as 1, but here AesEaxKeyFormat is encoded differently
KEY_TEMPLATE_1_NOT_NORMALIZED = r"""
 type_url: "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"
 value: "\n@\022>\022<\n0type.googleapis.com/google.crypto.tink.AesEaxKey\022\006\020\020\n\002\010\020\030\001"
 output_prefix_type: RAW
"""

# The same template as 1, but the inner AesEaxKeyFormat has a different iv_size
KEY_TEMPLATE_2 = r"""
 type_url: "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"
 value: "\n@\022>\022<\n0type.googleapis.com/google.crypto.tink.AesEaxKey\022\006\n\002\010\020\020\022\030\001"
 output_prefix_type: RAW
"""

KEY_TEMPLATE_1_COMMENTED_FORMAT = r"""
type_url: "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"
# value: [type.googleapis.com/google.crypto.tink.EciesAeadHkdfKeyFormat] {
#   params {
#     kem_params {
#       curve_type: UNKNOWN_CURVE
#       hkdf_hash_type: UNKNOWN_HASH
#       hkdf_salt: ""
#     }
#     dem_params {
#       aead_dem {
#         type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey"
#         # value: [type.googleapis.com/google.crypto.tink.AesEaxKeyFormat] {
#         #   params {
#         #     iv_size: 16
#         #   }
#         #   key_size: 16
#         # }
#         value: "\n\002\010\020\020\020"
#         output_prefix_type: TINK
#       }
#     }
#     ec_point_format: UNKNOWN_FORMAT
#   }
# }
value: "\n@\022>\022<\n0type.googleapis.com/google.crypto.tink.AesEaxKey\022\006\n\002\010\020\020\020\030\001"
output_prefix_type: RAW
""".strip()


class KeyUtilTest(parameterized.TestCase):

  def test_text_format_symmetric_key_template(self):
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
        value=b'\n\x02\x08\x10\x10\x10',
        output_prefix_type=tink_pb2.TINK)
    expected = r"""type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey"
# value: [type.googleapis.com/google.crypto.tink.AesEaxKeyFormat] {
#   params {
#     iv_size: 16
#   }
#   key_size: 16
# }
value: "\n\002\010\020\020\020"
output_prefix_type: TINK"""
    output = key_util.text_format(template)
    self.assertEqual(output, expected)
    # the output should be in text format, and result in the original template.
    self.assertEqual(
        text_format.Parse(output, tink_pb2.KeyTemplate()), template)

  def test_text_format_asymmetric_key_template(self):
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.EcdsaPrivateKey',
        value=b'\022\006\010\004\020\003\030\002',
        output_prefix_type=tink_pb2.TINK)
    expected = r"""type_url: "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
# value: [type.googleapis.com/google.crypto.tink.EcdsaKeyFormat] {
#   params {
#     hash_type: SHA512
#     curve: NIST_P384
#     encoding: DER
#   }
#   version: 0
# }
value: "\022\006\010\004\020\003\030\002"
output_prefix_type: TINK"""
    output = key_util.text_format(template)
    self.assertEqual(output, expected)
    # the output should be in text format, and result in the original template.
    self.assertEqual(
        text_format.Parse(output, tink_pb2.KeyTemplate()), template)

  def test_text_format_recursive_template(self):
    template = tink_pb2.KeyTemplate()
    text_format.Parse(KEY_TEMPLATE_1, template)
    output = key_util.text_format(template)
    self.assertEqual(output, KEY_TEMPLATE_1_COMMENTED_FORMAT)

  def test_text_format_normalizes_recursive_template(self):
    template1a = tink_pb2.KeyTemplate()
    text_format.Parse(KEY_TEMPLATE_1, template1a)

    template = tink_pb2.KeyTemplate()
    text_format.Parse(KEY_TEMPLATE_1_NOT_NORMALIZED, template)
    # Before the call, the value is different (different serializations)
    self.assertNotEqual(template1a.value, template.value)

    normalized_template = key_util.text_format(template)
    self.assertEqual(normalized_template, KEY_TEMPLATE_1_COMMENTED_FORMAT)

    # We explicitly test that the value has not been changed (since this
    # requirement needs an explicit copy in the code)
    self.assertNotEqual(template1a.value, template.value)

  def test_text_format_keyset(self):
    key = tink_pb2.Keyset.Key(
        key_data=tink_pb2.KeyData(
            type_url='type.googleapis.com/google.crypto.tink.AesGcmKey',
            value=b'\032\020Z\027\031\027\362\353\020\320\257p\271^\260\022\344\274',
            key_material_type=tink_pb2.KeyData.SYMMETRIC),
        status=tink_pb2.ENABLED,
        key_id=3588418072,
        output_prefix_type=tink_pb2.TINK)
    keyset = tink_pb2.Keyset(primary_key_id=3588418072)
    keyset.key.append(key)
    expected = r"""primary_key_id: 3588418072
key {
  key_data {
    type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
    # value: [type.googleapis.com/google.crypto.tink.AesGcmKey] {
    #   version: 0
    #   key_value: "Z\027\031\027\362\353\020\320\257p\271^\260\022\344\274"
    # }
    value: "\032\020Z\027\031\027\362\353\020\320\257p\271^\260\022\344\274"
    key_material_type: SYMMETRIC
  }
  status: ENABLED
  key_id: 3588418072
  output_prefix_type: TINK
}"""
    output = key_util.text_format(keyset)
    self.assertEqual(output, expected)
    # the output should be in text format, and result in the original template.
    self.assertEqual(
        text_format.Parse(output, tink_pb2.Keyset()), keyset)

  def test_compare_tink_messages(self):
    """Tests that all testdata have the expected format, including comments."""
    key_template_1 = text_format.Parse(KEY_TEMPLATE_1, tink_pb2.KeyTemplate())
    key_template_1_not_normalized = text_format.Parse(
        KEY_TEMPLATE_1_NOT_NORMALIZED, tink_pb2.KeyTemplate())
    key_util.assert_tink_proto_equal(self, key_template_1,
                                     key_template_1_not_normalized)
    key_template_2 = text_format.Parse(KEY_TEMPLATE_2, tink_pb2.KeyTemplate())

    with self.assertRaises(AssertionError):
      key_util.assert_tink_proto_equal(self, key_template_1, key_template_2)

  def test_parse_text_format_symmetric_key_template(self):
    serialized = r"""type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey"
# value: [type.googleapis.com/google.crypto.tink.AesEaxKeyFormat] {
#   params {
#     iv_size: 16
#   }
#   key_size: 16
# }
value: "\n\002\010\020\020\020"
output_prefix_type: TINK"""
    expected = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
        value=b'\n\x02\x08\x10\x10\x10',
        output_prefix_type=tink_pb2.TINK)

    parsed_template = tink_pb2.KeyTemplate()
    key_util.parse_text_format(serialized, parsed_template)
    self.assertEqual(parsed_template, expected)

  def test_parse_text_format_wrong_comment(self):
    serialized = r"""type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey"
value: "\n\002\010\020\020\020"
output_prefix_type: TINK"""

    parsed_template = tink_pb2.KeyTemplate()
    with self.assertRaises(AssertionError):
      key_util.parse_text_format(serialized, parsed_template)

  def test_parse_text_format_missing_comment(self):
    serialized = r"""type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey"
# value: [type.googleapis.com/google.crypto.tink.AesEaxKeyFormat] {
#   params {
#     iv_size: 16
#   }
#   key_size: 18
# }
value: "\n\002\010\020\020\020"
output_prefix_type: TINK"""

    parsed_template = tink_pb2.KeyTemplate()
    with self.assertRaises(AssertionError):
      key_util.parse_text_format(serialized, parsed_template)

  def test_assert_tink_proto_equal_does_not_modify_messages(self):
    """Tests that assert_tink_proto_equal does not modify the message."""
    key_template_1 = text_format.Parse(KEY_TEMPLATE_1, tink_pb2.KeyTemplate())
    key_template_1_original = text_format.Parse(
        KEY_TEMPLATE_1_NOT_NORMALIZED, tink_pb2.KeyTemplate())
    key_template_1_not_normalized = text_format.Parse(
        KEY_TEMPLATE_1_NOT_NORMALIZED, tink_pb2.KeyTemplate())
    key_util.assert_tink_proto_equal(self, key_template_1,
                                     key_template_1_not_normalized)
    self.assertEqual(key_template_1_original.value,
                     key_template_1_not_normalized.value)
    key_util.assert_tink_proto_equal(self, key_template_1_not_normalized,
                                     key_template_1)
    self.assertEqual(key_template_1_original.value,
                     key_template_1_not_normalized.value)

  def test_text_format_with_empty_value(self):
    expected = r"""type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
# value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
# }
value: ""
output_prefix_type: RAW"""

    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key',
        output_prefix_type=tink_pb2.RAW)
    formatted = key_util.text_format(template)
    self.assertEqual(formatted, expected)


if __name__ == '__main__':
  absltest.main()
