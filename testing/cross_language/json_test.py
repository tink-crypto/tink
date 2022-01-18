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
"""Cross-language tests for JSON serialization."""

from typing import Iterable

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import tink_pb2
from util import key_util
from util import supported_key_types
from util import testing_servers


def setUpModule():
  testing_servers.start('json')


def tearDownModule():
  testing_servers.stop()


def all_key_template_names() -> Iterable[str]:
  """Yields all key template names."""
  for key_type in supported_key_types.ALL_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class JsonTest(parameterized.TestCase):

  @parameterized.parameters(all_key_template_names())
  def test_to_from_json(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    for to_lang in supported_langs:
      json_keyset = testing_servers.keyset_to_json(to_lang, keyset)
      for from_lang in supported_langs:
        keyset2 = testing_servers.keyset_from_json(from_lang, json_keyset)
        key_util.assert_tink_proto_equal(
            self,
            tink_pb2.Keyset.FromString(keyset),
            tink_pb2.Keyset.FromString(keyset2),
            msg=('keysets are not equal when converting to JSON in '
                 '%s and back in %s' % (to_lang, from_lang)))


if __name__ == '__main__':
  absltest.main()
