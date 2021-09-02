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
"""Cross-language tests for the PrfSet primitive."""

# Placeholder for import for type annotations
from typing import Iterable, Text

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import prf

from tink.testing import keyset_builder
from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['prf']

OUTPUT_LENGTHS = [
    1, 2, 5, 10, 16, 17, 20, 32, 33, 48, 64, 65, 100, 256, 512, 1024
]


def all_prf_key_template_names() -> Iterable[Text]:
  """Yields all PRF key template names."""
  for key_type in supported_key_types.PRF_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


def all_prf_key_template_names_with_some_output_length():
  """Yields (prf_key_template_name, output_length) tuples."""
  for key_type in supported_key_types.PRF_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      for output_length in OUTPUT_LENGTHS:
        yield (key_template_name, output_length)


def gen_keyset(key_template_name: Text) -> bytes:
  builder = keyset_builder.new_keyset_builder()
  primary_key_id = builder.add_new_key(
      testing_servers.key_template('java', key_template_name))
  builder.set_primary_key(primary_key_id)
  return builder.keyset()


def gen_keyset_with_2_prfs() -> bytes:
  builder = keyset_builder.new_keyset_builder()
  builder.add_new_key(prf.prf_key_templates.HMAC_SHA256)
  primary_key_id = builder.add_new_key(prf.prf_key_templates.HKDF_SHA256)
  builder.set_primary_key(primary_key_id)
  return builder.keyset()


def setUpModule():
  prf.register()
  testing_servers.start('prf_set')


def tearDownModule():
  testing_servers.stop()


class PrfSetPythonTest(parameterized.TestCase):

  @parameterized.parameters(all_prf_key_template_names())
  def test_unsupported(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    keyset = gen_keyset(key_template_name)
    unsupported_languages = [
        lang for lang in SUPPORTED_LANGUAGES if lang not in supported_langs
    ]
    for lang in unsupported_languages:
      p = testing_servers.prf_set(lang, keyset)
      with self.assertRaises(
          tink.TinkError,
          msg='Language %s supports PRF compute with %s unexpectedly' %
          (p.lang, key_template_name)):
        p.primary().compute(b'input_data', output_length=16)

  @parameterized.parameters(all_prf_key_template_names())
  def test_supported(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    keyset = gen_keyset(key_template_name)
    input_data = b'This is some input data.'
    outputs = []
    for lang in supported_langs:
      p = testing_servers.prf_set(lang, keyset)
      outputs.append(p.primary().compute(input_data, 16))
    self.assertLen(outputs, len(supported_langs))
    self.assertLen(outputs[0], 16)
    self.assertLen(set(outputs), 1)

  @parameterized.parameters(
      all_prf_key_template_names_with_some_output_length())
  def test_compute_consistent_for_output_length(self, key_template_name,
                                                output_length):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    # This test checks that for a given output_length, either all
    # implementations fail or all produce the same value.
    self.assertNotEmpty(supported_langs)
    keyset = gen_keyset(key_template_name)
    input_data = b'This is some input data.'
    errors = {}
    outputs = {}
    for lang in supported_langs:
      try:
        p = testing_servers.prf_set(lang, keyset)
        outputs[lang] = p.primary().compute(input_data, output_length)
      except tink.TinkError as e:
        errors[lang] = e
    inconsistent_errors = bool(errors) and bool(outputs)
    inconsistent_output_values = len(set(outputs.values())) > 1
    if inconsistent_errors or inconsistent_output_values:
      self.fail('The PRF for template %s and output_length=%d is inconsistent: '
                'outputs = %s, errors = %s.' %
                (key_template_name, output_length, outputs, errors))

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_multiple_prfs(self, lang):
    keyset = gen_keyset_with_2_prfs()
    input_data = b'This is some input data.'
    output_length = 15
    p = testing_servers.prf_set(lang, keyset)
    primary_output = p.primary().compute(input_data, output_length)
    primary_id = p.primary_id()
    all_outputs = {
        key_id: f.compute(input_data, output_length)
        for key_id, f in p.all().items()
    }
    self.assertLen(all_outputs, 2)
    self.assertEqual(all_outputs[primary_id], primary_output)


if __name__ == '__main__':
  absltest.main()
