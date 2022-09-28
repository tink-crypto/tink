# Copyright 2022 Google LLC
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
"""Tests for _helpers."""

from absl.testing import absltest
from tink import aead

from tink_config import _helpers


class HelpersTest(absltest.TestCase):

  def test_get_all_key_types(self):
    self.assertNotEmpty(_helpers.all_key_types())

  def test_get_aead_key_types(self):
    self.assertNotEmpty(_helpers.key_types_for_primitive(aead.Aead))

  def test_key_type_from_type_url(self):
    self.assertEqual(
        _helpers.key_type_from_type_url(
            'type.googleapis.com/google.crypto.tink.AesGcmKey'), 'AesGcmKey')

  def test_key_type_from_type_url_wrong_prefix_throws(self):
    with self.assertRaises(ValueError):
      _helpers.key_type_from_type_url(
          'type.googleapis.com/google.crypto.tinkAesGcmKey')

  def test_key_type_from_type_url_wrong_key_type_throws(self):
    with self.assertRaises(ValueError):
      _helpers.key_type_from_type_url(
          'type.googleapis.com/google.crypto.tink.InvalidKeyType29981')

  def test_supported_languages_for_key_type(self):
    self.assertCountEqual(
        _helpers.supported_languages_for_key_type('AesGcmKey'),
        ['cc', 'java', 'go', 'python'])

  def test_supported_languages_for_key_type_invalid(self):
    with self.assertRaises(ValueError):
      _helpers.supported_languages_for_key_type('InvalidKeyType21b9a1')

  def test_supported_languages_for_primitive(self):
    self.assertCountEqual(
        _helpers.supported_languages_for_primitive(aead.Aead),
        ['cc', 'java', 'go', 'python'])

  def test_supported_languages_for_primitive_invalid(self):
    with self.assertRaises(KeyError):
      _helpers.supported_languages_for_primitive('not a primitive, a string')


if __name__ == '__main__':
  absltest.main()
