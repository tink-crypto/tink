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

from typing import List, Tuple

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import signature

from tink.proto import common_pb2
from tink.proto import rsa_ssa_pkcs1_pb2
from tink.proto import tink_pb2
import tink_config
from util import testing_servers

# 2048-bit modulus of the first test vector in
# https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
# This modulus uses the minimal two's-complement big-endian encoding, that's
# why it starts with a zero and has a leading 0 byte and has 257 bytes.
MODULUS_BYTES = bytes.fromhex(
    '00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808'
    'bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b7'
    '42bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0b'
    'beb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c914'
    '0ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7'
    'b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8'
    'f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f'
    '5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d'
)

# Same as MODULUS_BYTES, but with the least significant byte set to 0.
# Hence this modulus has 256 as a factor.
WEIRD_MODULUS_BYTES = bytes.fromhex(
    '00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808'
    'bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b7'
    '42bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0b'
    'beb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c914'
    '0ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7'
    'b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8'
    'f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f'
    '5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad800'
)

# Same as MODULUS_BYTES, but with the most significant bit set to 0, and
# the 2nd most significant bit set to 1. So this modulus has 2047 bits.
SHORT_MODULUS_BYTES = bytes.fromhex(
    '0073510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808'
    'bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b7'
    '42bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0b'
    'beb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c914'
    '0ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7'
    'b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8'
    'f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f'
    '5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d'
)

# big-endian encoding of 4th Fermat number F4 = 65537 = 2^16 + 1
F4_BYTES = bytes.fromhex('010001')

RSA_SSA_PKCS1_PUBLIC_KEY_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey'
)


def setUpModule():
  signature.register()
  testing_servers.start('aes_ctr_hmac_streaming_key_test')


def tearDownModule():
  testing_servers.stop()


def public_key_to_keyset(
    public_key: rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey,
    output_prefix_type: tink_pb2.OutputPrefixType,
) -> tink_pb2.Keyset:
  """Embeds a RsaSsaPkcs1PrivateKey with the output_prefix_type in a keyset."""
  return tink_pb2.Keyset(
      primary_key_id=1234,
      key=[
          tink_pb2.Keyset.Key(
              key_data=tink_pb2.KeyData(
                  type_url=RSA_SSA_PKCS1_PUBLIC_KEY_TYPE_URL,
                  value=public_key.SerializeToString(),
                  key_material_type=tink_pb2.KeyData.ASYMMETRIC_PUBLIC,
              ),
              output_prefix_type=output_prefix_type,
              status=tink_pb2.KeyStatusType.ENABLED,
              key_id=1234,
          )
      ],
  )


def valid_public_keys() -> (
    List[Tuple[str, rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey]]
):
  return [
      (
          '2048-bit public key with SHA256',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with SHA384',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA384
              ),
          ),
      ),
      (
          '2048-bit public key with SHA512',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA512
              ),
          ),
      ),
      (
          '2048-bit public key with SHA1',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with e=2^16+3',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=bytes.fromhex('010003'),
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with e=2^32-1',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=bytes.fromhex('ffffffff'),
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with many leading zeros in the modulus',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=bytes.fromhex('00000000') + MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key without any leading zeros in the modulus',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES[1:],
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with modulus divisible by 256',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=WEIRD_MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
  ]


def invalid_public_keys() -> (
    List[Tuple[str, rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey]]
):
  return [
      (
          '2048-bit public key with SHA224',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA224
              ),
          ),
      ),
      (
          '2048-bit public key with small e',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=bytes.fromhex('03'),
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA1
              ),
          ),
      ),
      (
          '2048-bit public key with 2^16-1',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              e=bytes.fromhex('00ffff'),
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA1
              ),
          ),
      ),
      (
          '2048-bit public key with an invalid e',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              # This e is even, which is invalid since e must be co-prime
              # with p-1 and q-1, which both are also even.
              e=bytes.fromhex('010002'),
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with e=2^32+1',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=MODULUS_BYTES,
              # BoringSSL (which gets used in C++, Python and Go) rejects values
              # for e with more than 32 bits.
              e=bytes.fromhex('0100000001'),
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2047-bit public key',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=0,
              n=SHORT_MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
      (
          '2048-bit public key with version 1',
          rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
              version=1,
              n=MODULUS_BYTES,
              e=F4_BYTES,
              params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
                  hash_type=common_pb2.HashType.SHA256
              ),
          ),
      ),
  ]


def valid_key_testcases():
  for lang in tink_config.supported_languages_for_key_type(
      'RsaSsaPkcs1PublicKey'
  ):
    for key_desc, key in valid_public_keys():
      if lang == 'go' and (
          key_desc == '2048-bit public key with e=2^16+3'
          or key_desc == '2048-bit public key with e=2^32-1'
      ):
        # Go only accepts e = F4 = 2^16 + 1 = 65537. See also b/274605582.
        continue
      yield ('%s: %s' % (key_desc, lang), lang, key)


def invalid_key_testcases():
  for lang in tink_config.supported_languages_for_key_type(
      'RsaSsaPkcs1PublicKey'
  ):
    for key_desc, key in invalid_public_keys():
      if lang == 'java' and key_desc == '2048-bit public key with e=2^32+1':
        # Java accepts large values for e. See also b/274605582.
        continue
      yield ('%s: %s' % (key_desc, lang), lang, key)


class RsaSsaPkcs1PublicKeyTest(parameterized.TestCase):
  """Tests specific for keys of type RsaSsaPkcs1PublicKey."""

  @parameterized.named_parameters(valid_key_testcases())
  def test_create_signature_verify_with_valid_key_success(
      self, lang: str, key: rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey
  ):
    keyset = public_key_to_keyset(key, tink_pb2.OutputPrefixType.TINK)
    testing_servers.remote_primitive(
        lang, keyset.SerializeToString(), signature.PublicKeyVerify
    )

  @parameterized.named_parameters(invalid_key_testcases())
  def test_create_signature_verify_with_invalid_key_fails(
      self, lang: str, key: rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey
  ):
    keyset = public_key_to_keyset(key, tink_pb2.OutputPrefixType.TINK)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive(
          lang, keyset.SerializeToString(), signature.PublicKeyVerify
      )

  def test_golang_rejects_f4_plus_2(self):
    """See also b/274605582."""
    key = rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
        version=0,
        n=MODULUS_BYTES,
        e=bytes.fromhex('010003'),
        params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
            hash_type=common_pb2.HashType.SHA256
        ),
    )
    keyset = public_key_to_keyset(key, tink_pb2.OutputPrefixType.TINK)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive(
          'go', keyset.SerializeToString(), signature.PublicKeyVerify
      )

  def test_java_accepts_large_e(self):
    """See also b/274605582."""
    key = rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
        version=0,
        n=MODULUS_BYTES,
        # 2^32 + 1
        e=bytes.fromhex('0100000001'),
        params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
            hash_type=common_pb2.HashType.SHA256
        ),
    )
    keyset = public_key_to_keyset(key, tink_pb2.OutputPrefixType.TINK)
    testing_servers.remote_primitive(
        'java', keyset.SerializeToString(), signature.PublicKeyVerify
    )


if __name__ == '__main__':
  absltest.main()
