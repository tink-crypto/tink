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
"""Tests that keys with higher version numbers are rejected."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead

from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import aes_gcm_siv_pb2
from tink.proto import chacha20_poly1305_pb2
from tink.proto import tink_pb2
from tink.proto import xchacha20_poly1305_pb2

from util import supported_key_types
from util import testing_servers

TYPE_URL_TO_SUPPORTED_LANGUAGES = {
    'type.googleapis.com/google.crypto.tink.' + key_type: langs
    for key_type, langs in supported_key_types.SUPPORTED_LANGUAGES.items()
}


def inc_version(keyset, key_class):
  """Parses the keyset and increments the version of each key by 1."""
  keyset_proto = tink_pb2.Keyset.FromString(keyset)
  for key in keyset_proto.key:
    key_proto = key_class.FromString(key.key_data.value)
    key_proto.version = key_proto.version + 1
    key.key_data.value = key_proto.SerializeToString()
  return keyset_proto.SerializeToString()


def gen_keys_for_aes_ctr_hmac_aead(keyset):
  keyset_proto = tink_pb2.Keyset.FromString(keyset)
  for key in keyset_proto.key:
    default_val = key.key_data.value

    key_proto = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey.FromString(default_val)
    key_proto.aes_ctr_key.version = key_proto.version + 1
    key.key_data.value = key_proto.SerializeToString()
    yield keyset_proto.SerializeToString()

    key_proto = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey.FromString(default_val)
    key_proto.hmac_key.version = key_proto.version + 1
    key.key_data.value = key_proto.SerializeToString()
    yield keyset_proto.SerializeToString()


def aead_test_cases():
  yield ('AES128_EAX', aes_eax_pb2.AesEaxKey)
  yield ('AES128_GCM', aes_gcm_pb2.AesGcmKey)
  yield ('AES128_GCM_SIV', aes_gcm_siv_pb2.AesGcmSivKey)
  yield ('AES128_CTR_HMAC_SHA256', aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey)
  yield ('CHACHA20_POLY1305', chacha20_poly1305_pb2.ChaCha20Poly1305Key)
  yield ('XCHACHA20_POLY1305', xchacha20_poly1305_pb2.XChaCha20Poly1305Key)


def setUpModule():
  aead.register()
  testing_servers.start('key_generation_consistency')


def tearDownModule():
  testing_servers.stop()


class KeyGenerationConsistencyTest(parameterized.TestCase):

  @parameterized.parameters(aead_test_cases())
  def test_inc_version_aead(self, name, key_class):
    """Increments the key version by one and checks they can't be used."""
    template = supported_key_types.KEY_TEMPLATE[name]
    for lang in TYPE_URL_TO_SUPPORTED_LANGUAGES[template.type_url]:
      keyset = testing_servers.new_keyset(lang, template)
      keyset1 = inc_version(keyset, key_class)
      aead_primitive = testing_servers.aead(lang, keyset1)
      with self.assertRaises(tink.TinkError):
        _ = aead_primitive.encrypt(b'foo', b'bar')

  def test_inc_version_aead_aes_ctr_hmac_subkeys(self):
    """Increments the subkey versions by one and check they can't be used."""
    template = supported_key_types.KEY_TEMPLATE['AES128_CTR_HMAC_SHA256']
    for lang in TYPE_URL_TO_SUPPORTED_LANGUAGES[template.type_url]:
      keyset = testing_servers.new_keyset(lang, template)
      for keyset1 in gen_keys_for_aes_ctr_hmac_aead(keyset):
        aead_primitive = testing_servers.aead(lang, keyset1)
        with self.assertRaises(tink.TinkError):
          _ = aead_primitive.encrypt(b'foo', b'bar')


if __name__ == '__main__':
  absltest.main()
