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

from google3.net.proto2.python.public import text_format
from tink.proto import tink_pb2
from util import key_util

KEYSET_A = r"""
  primary_key_id: 4223424880
  key {
    key_data {
      type_url: "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
      value: "\" \321L\232\025n*\335.w\023\311\242\035\252^B\024w\305lwa\261K\341\037\2353Yy\3521\032 ^}`\277\341|\364\355\013\035>\275&\3726fu\003\364\373\267\213e\320\030(\234\246b\352\362\311\022\006\030\002\020\002\010\003"
      key_material_type: ASYMMETRIC_PUBLIC
    }
    status: ENABLED
    key_id: 4223424880
    output_prefix_type: CRUNCHY
  }"""

# The same keyset as A, but here EcdsaPublicKey is encoded differently
KEYSET_B = r"""
  primary_key_id: 4223424880
  key {
    key_data {
      type_url: "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
      value: "\022\006\010\003\020\002\030\002\032 ^}`\277\341|\364\355\013\035>\275&\3726fu\003\364\373\267\213e\320\030(\234\246b\352\362\311\" \321L\232\025n*\335.w\023\311\242\035\252^B\024w\305lwa\261K\341\037\2353Yy\3521"
      key_material_type: ASYMMETRIC_PUBLIC
    }
    status: ENABLED
    key_id: 4223424880
    output_prefix_type: CRUNCHY
  }
"""


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
# }
value: "\022\006\010\004\020\003\030\002"
output_prefix_type: TINK"""
    output = key_util.text_format(template)
    self.assertEqual(output, expected)
    # the output should be in text format, and result in the original template.
    self.assertEqual(
        text_format.Parse(output, tink_pb2.KeyTemplate()), template)

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
    keyset_a = text_format.Parse(KEYSET_A, tink_pb2.Keyset())
    keyset_b = text_format.Parse(KEYSET_B, tink_pb2.Keyset())
    key_util.assert_tink_proto_equal(self, keyset_a, keyset_b)

    keyset_b.primary_key_id = 4223424881
    with self.assertRaises(AssertionError):
      key_util.assert_tink_proto_equal(self, keyset_a, keyset_b)


if __name__ == '__main__':
  absltest.main()
