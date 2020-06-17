# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.testing.cross_language.util.testing_server."""

from absl.testing import absltest
from absl.testing import parameterized


import tink
from tink import aead

from util import testing_servers


def setUpModule():
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class TestingServersTest(parameterized.TestCase):

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_testing_servers(self, lang):
    keyset_handle = testing_servers.new_keyset_handle(
        lang, aead.aead_key_templates.AES128_GCM)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    aead_primitive = testing_servers.aead(lang, keyset_handle)
    ciphertext = aead_primitive.encrypt(plaintext, associated_data)
    output = aead_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    with self.assertRaises(tink.TinkError):
      aead_primitive.decrypt(b'foo', associated_data)


if __name__ == '__main__':
  absltest.main()
