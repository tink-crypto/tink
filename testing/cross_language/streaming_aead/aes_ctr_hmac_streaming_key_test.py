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

import binascii
import io

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import streaming_aead

from tink.proto import aes_ctr_hmac_streaming_pb2
from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import tink_pb2
import tink_config
from util import testing_servers


def setUpModule():
  streaming_aead.register()
  testing_servers.start('aes_ctr_hmac_streaming_key_test')


def tearDownModule():
  testing_servers.stop()


def to_keyset(
    key: aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey,
) -> tink_pb2.Keyset:
  """Embeds a AesCtrHmacStreamingKey in some way in a keyset."""
  return tink_pb2.Keyset(
      primary_key_id=1234,
      key=[
          tink_pb2.Keyset.Key(
              key_data=tink_pb2.KeyData(
                  type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey',
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
    aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey
):
  """Creates a simple, valid AesCtrHmacStreamingKey object."""
  return aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey(
      version=0,
      params=aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingParams(
          ciphertext_segment_size=512,
          derived_key_size=16,
          hkdf_hash_type=common_pb2.HashType.SHA256,
          hmac_params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=16
          ),
      ),
      key_value=b'0123456789abcdef',
  )


def lang_and_valid_keys_create_and_encrypt():
  result = []
  langs = tink_config.supported_languages_for_key_type('AesCtrHmacStreamingKey')

  key = simple_valid_key()
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  assert key.params.derived_key_size == 16
  key.params.derived_key_size = 32
  key.key_value = b'0123456789abcdef0123456789abcdef'
  for lang in langs:
    result.append((lang, key))

  ## TAG SIZES
  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA1
  key.params.hmac_params.tag_size = 10
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA1
  key.params.hmac_params.tag_size = 11
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA1
  key.params.hmac_params.tag_size = 20
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA256
  key.params.hmac_params.tag_size = 10
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA256
  key.params.hmac_params.tag_size = 11
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA256
  key.params.hmac_params.tag_size = 32
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA512
  key.params.hmac_params.tag_size = 10
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA512
  key.params.hmac_params.tag_size = 11
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA512
  key.params.hmac_params.tag_size = 64
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
  key.params.ciphertext_segment_size = (
      key.params.derived_key_size + key.params.hmac_params.tag_size + 9
  )
  for lang in langs:
    result.append((lang, key))

  return result


def lang_and_valid_keys_create_only():
  result = lang_and_valid_keys_create_and_encrypt()
  langs = tink_config.supported_languages_for_key_type('AesCtrHmacStreamingKey')

  # TODO(b/268193523): Java crashes with ciphertext_segment_size = 2**31 - 1
  key = simple_valid_key()
  key.params.ciphertext_segment_size = 2**31 - 1
  for lang in langs:
    result.append((lang, key))

  return result


def lang_and_invalid_keys():
  result = []
  langs = tink_config.supported_languages_for_key_type('AesCtrHmacStreamingKey')

  key = simple_valid_key()
  key.params.derived_key_size = 24
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA224
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hkdf_hash_type = common_pb2.HashType.SHA384
  for lang in langs:
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
  key.params.ciphertext_segment_size = (
      key.params.derived_key_size + key.params.hmac_params.tag_size + 8
  )
  for lang in langs:
    result.append((lang, key))

  ## Tag sizes
  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA1
  key.params.hmac_params.tag_size = 9
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA1
  key.params.hmac_params.tag_size = 21
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA256
  key.params.hmac_params.tag_size = 9
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA256
  key.params.hmac_params.tag_size = 33
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA512
  key.params.hmac_params.tag_size = 9
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA512
  key.params.hmac_params.tag_size = 65
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA224
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.hmac_params.hash = common_pb2.HashType.SHA384
  for lang in langs:
    result.append((lang, key))

  key = simple_valid_key()
  key.params.ciphertext_segment_size = 2**31
  for lang in langs:
    result.append((lang, key))

  return result


class AesCtrHmacStreamingKeyTest(parameterized.TestCase):
  """Tests specific for keys of type AesCtrHmacStreamingKey.

  See https://developers.google.com/tink/streaming-aead/aes_ctr_hmac_streaming
  for the documentation.
  """

  @parameterized.parameters(lang_and_valid_keys_create_only())
  def test_create_streaming_aead(
      self, lang: str, key: aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey
  ):
    keyset = to_keyset(key)
    testing_servers.remote_primitive(
        lang, keyset.SerializeToString(), streaming_aead.StreamingAead
    )

  @parameterized.parameters(lang_and_valid_keys_create_and_encrypt())
  def test_create_streaming_aead_encrypt_decrypt(
      self, lang: str, key: aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey
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
      self, lang: str, key: aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey
  ):
    keyset = to_keyset(key)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive(
          lang, keyset.SerializeToString(), streaming_aead.StreamingAead
      )

  @parameterized.parameters(
      tink_config.supported_languages_for_key_type('AesCtrHmacStreamingKey')
  )
  def test_manually_created_test_vector(self, lang: str):
    """Tests using a ciphertext created by looking at the documentation.

    See https://developers.google.com/tink/streaming-aead/aes_ctr_hmac_streaming
    for the documentation. The goal is to ensure that the documentation is
    clear; we expect readers to read this with the documentation.

    Args:
      lang: The language to test.
    """

    def xor(b1: bytes, b2: bytes) -> bytes:
      return bytes(i ^ j for (i, j) in zip(b1, b2))

    h2b = binascii.a2b_hex

    key = aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey(
        version=0,
        params=aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingParams(
            ciphertext_segment_size=64,
            derived_key_size=16,
            hkdf_hash_type=common_pb2.HashType.SHA1,
            hmac_params=hmac_pb2.HmacParams(
                hash=common_pb2.HashType.SHA256, tag_size=32
            ),
        ),
        key_value=h2b('6eb56cdc726dfbe5d57f2fcdc6e9345b')
    )
    # We set the message to be:
    msg = b'This is a fairly long plaintext. However, it is not crazy long.'
    #
    # We set the associated data to be:
    aad = b'aad'

    # We picked the header at random: Note the length is 24 = 0x18.
    header_length = h2b('18')
    salt = h2b('93b3af5e14ab378d065addfc8484da64')
    nonce_prefix = h2b('2c0862877baea8')
    header = header_length + salt + nonce_prefix
    # hkdf.hkdf_sha1(ikm=key_value, salt=header_salt, info=aad, size=48) gives
    # '66dd511791296a6cfc94a24041fcab9f' +
    # '0f736d6e85c448c2c8cc30f094d7e2d89e1a4c6a2dea4e9c8d1d2015e54c609a'
    # aes_key = h2b('66dd511791296a6cfc94a24041fcab9f')
    # hmac_key = h2b(
    #        '0f736d6e85c448c2c8cc30f094d7e2d89e1a4c6a2dea4e9c8d1d2015e54c609a')

    # We next split the message:
    # len(msg) = 63.
    # len(M_0) = 8 = CiphertextSegmentSize(64) - Headerlength(24) - TagSize(32)
    # len(M_1) = 32 = CiphertextSegmentSize(64) - TagSize(32)
    # len(M_2) = 23 < CiphertextSegmentSize(64) - TagSize(32)
    msg_0 = msg[:8]
    msg_1 = msg[8:40]
    msg_2 = msg[40:]

    # Relevant AES computations with key = 66dd511791296a6cfc94a24041fcab9f
    #
    # nonce_prefix + segment_nr + b + i   | Out
    # -----------------------------------------------------------------------
    # 2c0862877baea8 00000000 00 00000000 | ea8e18301bd57bfdd2f903025950c827
    # 2c0862877baea8 00000001 00 00000000 | 2999c8ea5401704243c8cd77929fd526
    # 2c0862877baea8 00000001 00 00000001 | 17fec5542a842446251bb2f3a81f6249
    # 2c0862877baea8 00000002 01 00000000 | 70fe58e44835a6602952749e763637d9
    # 2c0862877baea8 00000002 01 00000001 | d973bca83580867766f38b056d735902
    #
    c0 = xor(msg_0, h2b(b'ea8e18301bd57bfd'))
    c1 = xor(msg_1[:16], h2b('2999c8ea5401704243c8cd77929fd526')) + xor(
        msg_1[16:32], h2b('17fec5542a842446251bb2f3a81f6249')
    )
    c2 = xor(msg_2[:16], h2b('70fe58e44835a6602952749e763637d9')) + xor(
        msg_2[16:], h2b('d973bca8358086')
    )

    # T0 = hmac(key = hmac_key, h2b('2c0862877baea8000000000000000000' + c0)
    t0 = h2b('8303ca71c04d8e06e1b01cff7c1178af47dac031517b1f6a2d9be84105677a68')
    # T1 = hmac(key = hmac_key, h2b('2c0862877baea8000000010000000000' + c1)
    t1 = h2b('834d890839f37f762caddc029cc673300ff107fd51f9a62058fcd00befc362e5')
    # T2 = hmac(key = hmac_key, h2b('2c0862877baea8000000020100000000' + c2)
    t2 = h2b('5fb0c893903271af38380c2f355cb85e5ec571648513123321bde0c6042f43c7')

    ciphertext = header + c0 + t0 + c1 + t1 + c2 + t2

    keyset = to_keyset(key)
    saead = testing_servers.remote_primitive(
        lang, keyset.SerializeToString(), streaming_aead.StreamingAead
    )

    self.assertEqual(
        saead.new_decrypting_stream(io.BytesIO(ciphertext), aad).read(),
        msg,
    )

if __name__ == '__main__':
  absltest.main()
