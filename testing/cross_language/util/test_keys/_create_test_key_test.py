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

"""Tests for create_test_key."""

from absl.testing import absltest
from tink import aead

from tink.proto import aes_gcm_pb2
from tink.proto import tink_pb2
from util import key_util
from util import test_keys


def _do_not_use_stored_key(_: tink_pb2.KeyTemplate) -> bool:
  return False


def _use_stored_key(_: tink_pb2.KeyTemplate) -> bool:
  return True


def setUpModule():
  aead.register()


class CreateTestKeyTest(absltest.TestCase):

  def test_get_new_aes_gcm_key(self):
    """Tests that AES GCM Keys can be generated on the fly."""
    template = aead.aead_key_templates.AES128_GCM
    key = test_keys.new_or_stored_key(template, test_keys.TestKeysContainer(),
                                      _do_not_use_stored_key)
    self.assertEqual(key.key_data.type_url,
                     'type.googleapis.com/google.crypto.tink.AesGcmKey')
    parsed_key = aes_gcm_pb2.AesGcmKey()
    parsed_key.ParseFromString(key.key_data.value)
    self.assertLen(parsed_key.key_value, 16)

  def test_get_precomputed_aes_gcm_key(self):
    """Tests a key in the container will be retrieved if needed."""

    # First, create a template and a key manually
    template = aead.aead_key_templates.AES128_GCM
    key = test_keys.new_or_stored_key(template, test_keys.TestKeysContainer(),
                                      _do_not_use_stored_key)
    # Insert the key into a container
    container_with_aes_gcm_key = test_keys.TestKeysContainer()
    container_with_aes_gcm_key.add_key(
        key_util.text_format(template), key_util.text_format(key))
    key_from_create = test_keys.new_or_stored_key(template,
                                                  container_with_aes_gcm_key,
                                                  _use_stored_key)
    # It suffices to compare the key material to check if the keys are the same
    self.assertEqual(key.key_data.value, key_from_create.key_data.value)

  def test_get_non_existing_precomputed_aes_gcm_key(self):
    """Tests a key in the container will be retrieved if needed."""

    template = aead.aead_key_templates.AES128_GCM
    container = test_keys.TestKeysContainer()
    with self.assertRaises(ValueError):
      test_keys.new_or_stored_key(template, container, _use_stored_key)

  def test_get_keyset_new_aes_gcm_key(self):
    """Tests that AES GCM Keys can be generated on the fly."""
    template = aead.aead_key_templates.AES128_GCM
    keyset = test_keys.new_or_stored_keyset(
        template,
        test_keys.TestKeysContainer(),
        _do_not_use_stored_key)
    self.assertLen(keyset.key, 1)
    self.assertEqual(keyset.primary_key_id, keyset.key[0].key_id)
    self.assertEqual(keyset.key[0].key_data.type_url,
                     'type.googleapis.com/google.crypto.tink.AesGcmKey')
    parsed_key = aes_gcm_pb2.AesGcmKey()
    parsed_key.ParseFromString(keyset.key[0].key_data.value)
    self.assertLen(parsed_key.key_value, 16)

  def test_get_keyset_precomputed_aes_gcm_key(self):
    """Tests a key in the container will be retrieved if needed."""

    # First, create a template and a key manually
    template = aead.aead_key_templates.AES128_GCM
    key = test_keys.new_or_stored_key(template, test_keys.TestKeysContainer(),
                                      _do_not_use_stored_key)
    # Insert the key into a container
    container_with_aes_gcm_key = test_keys.TestKeysContainer()
    container_with_aes_gcm_key.add_key(
        key_util.text_format(template), key_util.text_format(key))
    keyset = test_keys.new_or_stored_keyset(template,
                                            container_with_aes_gcm_key,
                                            _use_stored_key)
    # It suffices to compare the key material to check if the keys are the same
    self.assertLen(keyset.key, 1)
    self.assertEqual(keyset.primary_key_id, keyset.key[0].key_id)
    self.assertEqual(keyset.key[0].key_data.type_url,
                     'type.googleapis.com/google.crypto.tink.AesGcmKey')
    self.assertEqual(key.key_data.value, keyset.key[0].key_data.value)

  def test_get_keyset_non_existing_precomputed_aes_gcm_key(self):
    """Tests a key in the container will be retrieved if needed."""

    template = aead.aead_key_templates.AES128_GCM
    container = test_keys.TestKeysContainer()
    with self.assertRaises(ValueError):
      test_keys.new_or_stored_keyset(template, container, _use_stored_key)

  def test_key_from_test_keys_db_get_chacha_key(self):
    """Tests that with only one arguments we get keys from _test_keys_db.py."""

    parsed_template = tink_pb2.KeyTemplate()
    key_util.parse_text_format(
        serialized=r"""type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
# value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
# }
value: ""
output_prefix_type: RAW""",
        msg=parsed_template)
    key = test_keys.new_or_stored_key(parsed_template)
    # The same value as in _test_keys_db for the raw key.
    self.assertEqual(
        key.key_data.value,
        b'\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611'
    )

  def test_keyset_from_test_keys_db_get_chacha_key(self):
    """Tests that with only one arguments we get keys from _test_keys_db.py."""

    parsed_template = tink_pb2.KeyTemplate()
    key_util.parse_text_format(
        serialized=r"""type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
# value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
# }
value: ""
output_prefix_type: RAW""",
        msg=parsed_template)
    keyset = test_keys.new_or_stored_keyset(parsed_template)
    self.assertLen(keyset.key, 1)
    # The same value as in _test_keys_db for the raw key.
    self.assertEqual(
        keyset.key[0].key_data.value,
        b'\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611'
    )


if __name__ == '__main__':
  absltest.main()
