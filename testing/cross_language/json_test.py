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

# Placeholder for import for type annotations
from typing import Iterable, Text

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import tink_pb2
from util import supported_key_types
from util import testing_servers


def setUpModule():
  testing_servers.start('json')


def tearDownModule():
  testing_servers.stop()


def _keyset_proto(keyset: bytes) -> tink_pb2.Keyset:
  keyset_proto = tink_pb2.Keyset()
  keyset_proto.ParseFromString(keyset)
  # We sort the keys, since we want keysets to be considered equal even if the
  # keys are in different order.
  keyset_proto.key.sort(key=lambda k: k.key_id)
  return keyset_proto


def _is_equal_keyset(keyset1: bytes, keyset2: bytes) -> bool:
  """Checks if two keyset are equal, and have the exact same keydata.value."""
  # Keydata.value are serialized protos. This serialization is usually not
  # deterministic, as it is a unsorted list of key value pairs.
  # But since JSON serialization does not change keyset.value, we can simply
  # require these values to be exactly the same in this test. In other tests,
  # this might be too strict.
  return _keyset_proto(keyset1) == _keyset_proto(keyset2)


def all_key_template_names() -> Iterable[Text]:
  """Yields all key template names."""
  for key_type in supported_key_types.ALL_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class JsonTest(parameterized.TestCase):

  def test_is_equal_keyset(self):
    keyset1 = tink_pb2.Keyset()
    key11 = keyset1.key.add()
    key11.key_id = 21
    key12 = keyset1.key.add()
    key12.key_id = 42
    keyset2 = tink_pb2.Keyset()
    key21 = keyset2.key.add()
    key21.key_id = 42
    key22 = keyset2.key.add()
    key22.key_id = 21
    self.assertTrue(_is_equal_keyset(keyset1.SerializeToString(),
                                     keyset2.SerializeToString()))

  def test_is_not_equal_keyset(self):
    keyset1 = tink_pb2.Keyset()
    key11 = keyset1.key.add()
    key11.key_id = 21
    key12 = keyset1.key.add()
    key12.key_id = 42
    keyset2 = tink_pb2.Keyset()
    key3 = keyset2.key.add()
    key3.key_id = 21
    self.assertFalse(_is_equal_keyset(keyset1.SerializeToString(),
                                      keyset2.SerializeToString()))

  def assertEqualKeyset(self, keyset1: bytes, keyset2: bytes):
    if not _is_equal_keyset(keyset1, keyset2):
      self.fail('these keysets are not equal: \n%s\n \n%s\n'
                % (_keyset_proto(keyset1), _keyset_proto(keyset2)))

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
        self.assertEqualKeyset(keyset, keyset2)


if __name__ == '__main__':
  absltest.main()
