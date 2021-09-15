# Copyright 2021 Google LLC
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
"""Tests that keys are consistently accepted or rejected in all languages."""

# Placeholder for import for type annotations
from typing import Iterable, Text

from absl.testing import absltest
from absl.testing import parameterized

import tink

from util import key_util
from util import supported_key_types
from util import testing_servers


def all_template_names() -> Iterable[Text]:
  for names in supported_key_types.KEY_TEMPLATE_NAMES.values():
    for name in names:
      yield name


# These key templates are not defined in these languages.
UNDEFINED_TEMPLATES = [
    ('ECDSA_P384_SHA384_IEEE_P1363', 'cc'),
    ('ECDSA_P384_SHA384_IEEE_P1363', 'java'),
    ('ECDSA_P384_SHA384_IEEE_P1363', 'go'),
    ('AES128_GCM_HKDF_1MB', 'cc'),
    ('AES128_CTR_HMAC_SHA256_1MB', 'cc'),
    ('AES256_CTR_HMAC_SHA256_1MB', 'cc'),
    ('ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM', 'go'),
    ('ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256', 'go'),
    ('ECDSA_P256_IEEE_P1363', 'go'),
    ('ECDSA_P384_IEEE_P1363', 'go'),
    ('ECDSA_P521_IEEE_P1363', 'go'),
    ('AES128_GCM_SIV', 'go'),
    ('AES256_GCM_SIV', 'go'),
    ('AES128_EAX_RAW', 'cc'),
    ('AES256_EAX_RAW', 'cc'),
    ('AES128_GCM_SIV_RAW', 'cc'),
    ('AES256_GCM_SIV_RAW', 'cc'),
    ('AES128_GCM_SIV_RAW', 'go'),
    ('AES256_GCM_SIV_RAW', 'go'),
    ('AES128_GCM_RAW', 'cc'),
    ('AES128_GCM_RAW', 'go'),
    ('AES128_CTR_HMAC_SHA256_RAW', 'cc'),
    ('AES256_CTR_HMAC_SHA256_RAW', 'cc'),
    ('AES128_CTR_HMAC_SHA256_RAW', 'go'),
    ('AES256_CTR_HMAC_SHA256_RAW', 'go'),
    ('CHACHA20_POLY1305_RAW', 'go'),
    ('XCHACHA20_POLY1305_RAW', 'cc'),
    ('XCHACHA20_POLY1305_RAW', 'go'),
]


def setUpModule():
  testing_servers.start('key_generation_consistency')


def tearDownModule():
  testing_servers.stop()


class KeyGenerationConsistencyTest(parameterized.TestCase):

  @parameterized.parameters(all_template_names())
  def test_key_template_is_consistent(self, template_name):
    langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        template_name]
    templates = {}
    for lang in langs:
      if (template_name, lang) in UNDEFINED_TEMPLATES:
        with self.assertRaises(
            tink.TinkError,
            msg=('(%s, %s) is in UNDEFINED_TEMPLATES, but does not fail.' %
                 (template_name, lang))):
          testing_servers.key_template(lang, template_name)
        continue
      try:
        templates[lang] = testing_servers.key_template(lang, template_name)
      except tink.TinkError as e:
        self.fail('(%s,%s): %s' % (lang, template_name, e))
    if len(templates) <= 1:
      # nothing to check.
      return
    langs = list(templates.keys())
    template = templates[langs[0]]
    for lang in langs[1:]:
      key_util.assert_tink_proto_equal(
          self,
          templates[lang],
          template,
          msg=('templates in %s and %s are not equal:' % (langs[0], lang)))


if __name__ == '__main__':
  absltest.main()
