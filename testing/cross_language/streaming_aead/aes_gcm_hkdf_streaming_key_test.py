# Copyright 2023 Google LLC
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

import io

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import streaming_aead

from tink.proto import aes_gcm_hkdf_streaming_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
import tink_config
from util import testing_servers


def setUpModule():
  streaming_aead.register()
  testing_servers.start('aes_gcm_hkdf_streaming_key_test')


def tearDownModule():
  testing_servers.stop()


def to_keyset(
    key: aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey,
) -> tink_pb2.Keyset:
  """Embeds a AesGcmHkdfStreamingKey in some way in a keyset."""
  return tink_pb2.Keyset(
      primary_key_id=1234,
      key=[
          tink_pb2.Keyset.Key(
              key_data=tink_pb2.KeyData(
                  type_url='type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey',
                  value=key.SerializeToString(),
                  key_material_type='SYMMETRIC',
              ),
              output_prefix_type=tink_pb2.OutputPrefixType.RAW,
              status=tink_pb2.KeyStatusType.ENABLED,
              key_id=1234,
          )
      ],
  )


def simple_valid_key() -> (
    aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey
):
  """Creates a simple, valid AesGcmHkdfStreamingKey object."""
  return aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey(
      version=0,
      params=aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingParams(
          ciphertext_segment_size=512,
          derived_key_size=16,
          hkdf_hash_type=common_pb2.HashType.SHA256,
      ),
      key_value=b'0123456789abcdef',
  )


def lang_and_valid_keys_create_and_encrypt():
  result = []
  langs = tink_config.supported_languages_for_key_type('AesGcmHkdfStreamingKey')

  key = simple_valid_key()
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  assert key.params.derived_key_size == 16
  key.params.derived_key_size = 32
  key.key_value = b'0123456789abcdef0123456789abcdef'
  for lang in langs:
    result.append((lang, key))

  # HKDF Hash Type:
  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA1
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA256
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA512
  for lang in langs:
    result.append((lang, key))

  # Minimum ciphertext_segment_size
  key = simple_valid_key()
  key.params.ciphertext_segment_size = key.params.derived_key_size + 25
  for lang in langs:
    result.append((lang, key))

  return result


def lang_and_valid_keys_create_only():
  result = lang_and_valid_keys_create_and_encrypt()
  langs = tink_config.supported_languages_for_key_type('AesGcmHkdfStreamingKey')

  # TODO(b/268193523): Java crashes with ciphertext_segment_size = 2**31 - 1
  key = simple_valid_key()
  key.params.ciphertext_segment_size = 2**31 - 1
  for lang in langs:
    result.append((lang, key))

  return result


def lang_and_invalid_keys():
  result = []
  langs = tink_config.supported_languages_for_key_type('AesGcmHkdfStreamingKey')

  key = simple_valid_key()
  key.params.derived_key_size = 24
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA224
  for lang in langs:
    # TODO(tholenst): Fix this in golang and java
    if lang not in ['go', 'java']:
      result.append((lang, key))

  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA384
  for lang in langs:
    # TODO(tholenst): Fix this in golang and java
    if lang not in ['go', 'java']:
      result.append((lang, key))

  # Check requirement len(InitialKeyMaterial) >= DerivedKeySize
  key = simple_valid_key()
  key.key_value = b'0123456789abcdef'
  key.params.derived_key_size = 32
  for lang in langs:
    result.append((lang, key))

  # HKDF Hash Type:
  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.UNKNOWN_HASH
  for lang in langs:
    result.append((lang, key))

  # Minimum ciphertext_segment_size
  key = simple_valid_key()
  key.params.ciphertext_segment_size = key.params.derived_key_size + 24
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.ciphertext_segment_size = 2**31
  for lang in langs:
    # TODO(tholenst): Fix this in golang
    if lang != 'go':
      result.append((lang, key))

  return result


class AesGcmHkdfStreamingKeyTest(parameterized.TestCase):
  """Tests specific for keys of type AesGcmHkdfStreamingKey.

  See https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming
  for the documentation.
  """

  @parameterized.parameters(lang_and_valid_keys_create_only())
  def test_create_streaming_aead(
      self, lang: str, key: aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey
  ):
    keyset = to_keyset(key)
    testing_servers.remote_primitive(
        lang, keyset.SerializeToString(), streaming_aead.StreamingAead
    )

  @parameterized.parameters(lang_and_valid_keys_create_and_encrypt())
  def test_create_streaming_aead_encrypt_decrypt(
      self, lang: str, key: aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey
  ):
    keyset = to_keyset(key)
    saead = testing_servers.remote_primitive(
        lang, keyset.SerializeToString(), streaming_aead.StreamingAead
    )
    plaintext = b'some plaintext'
    ad = b'associated_data'
    ciphertext = saead.new_encrypting_stream(
        io.BytesIO(plaintext), ad
    ).read()
    self.assertEqual(
        saead.new_decrypting_stream(
            io.BytesIO(ciphertext), ad
        ).read(),
        plaintext,
    )

  @parameterized.parameters(lang_and_invalid_keys())
  def test_create_streaming_aead_invalid_key_fails(
      self, lang: str, key: aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey
  ):
    keyset = to_keyset(key)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive(
          lang, keyset.SerializeToString(), streaming_aead.StreamingAead
      )


if __name__ == '__main__':
  absltest.main()
