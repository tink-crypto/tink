# Copyright 2020 Google LLC
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
"""Tests for tink.testing.cross_language.supported_key_types."""

from absl.testing import absltest
from util import supported_key_types


def all_key_template_names():
  for _, names in supported_key_types.KEY_TEMPLATE_NAMES.items():
    for name in names:
      yield name


class SupportedKeyTypesTest(absltest.TestCase):

  def test_all_key_types_present(self):
    self.assertEqual(
        list(supported_key_types.SUPPORTED_LANGUAGES.keys()),
        supported_key_types.ALL_KEY_TYPES)
    self.assertEqual(
        list(supported_key_types.KEY_TEMPLATE_NAMES.keys()),
        supported_key_types.ALL_KEY_TYPES)

  def test_all_key_templates_present(self):
    self.assertEqual(
        list(all_key_template_names()),
        list(supported_key_types.KEY_TEMPLATE.keys()))

  def test_supported_lang_by_template_name_all_present(self):
    self.assertEqual(
        list(all_key_template_names()),
        list(supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME.keys()))

  def test_supported_langauges_by_template_name(self):
    self.assertEqual(
        supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
            'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM'],
        ['cc', 'java', 'go', 'python'])
    self.assertEqual(
        supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
            'ECIES_P256_HKDF_HMAC_SHA256_XCHACHA20_POLY1305'], ['cc', 'python'])


if __name__ == '__main__':
  absltest.main()
