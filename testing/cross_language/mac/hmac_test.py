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

import os
import random

from absl.testing import absltest
from absl.testing import parameterized
import tink

from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import tink_pb2
import tink_config
from util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('aes_ctr_hmac_streaming_key_test')


def tearDownModule():
  testing_servers.stop()


def to_keyset(
    key: hmac_pb2.HmacKey, output_prefix_type: tink_pb2.OutputPrefixType
) -> tink_pb2.Keyset:
  """Embeds a HmacKey with the output_prefix_type in a keyset."""
  return tink_pb2.Keyset(
      primary_key_id=1234,
      key=[
          tink_pb2.Keyset.Key(
              key_data=tink_pb2.KeyData(
                  type_url='type.googleapis.com/google.crypto.tink.HmacKey',
                  value=key.SerializeToString(),
                  key_material_type='SYMMETRIC',
              ),
              output_prefix_type=output_prefix_type,
              status=tink_pb2.KeyStatusType.ENABLED,
              key_id=1234,
          )
      ],
  )


def valid_keys():
  return [
      # Try SHA1 tag sizes
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=15
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=20
          ),
      ),
      # Try SHA1 key sizes
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(17),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(30),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      # Very large key
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(1274),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      # Different hash functions, min tag & key size.
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA224, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA384, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA512, tag_size=10
          ),
      ),
  ]


def invalid_keys():
  return [
      # Short key size
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(9),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      # Too short tag
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA224, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA384, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA512, tag_size=9
          ),
      ),
      # Too long tag
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=21
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA224, tag_size=29
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=33
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA384, tag_size=49
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA512, tag_size=65
          ),
      ),
  ]


def valid_lang_and_key():
  for lang in tink_config.supported_languages_for_key_type('HmacKey'):
    for key in valid_keys():
      yield (lang, key)


def consistency_test_cases():
  for lang1 in tink_config.supported_languages_for_key_type('HmacKey'):
    for lang2 in tink_config.supported_languages_for_key_type('HmacKey'):
      for key in valid_keys():
        for output_prefix_type in [tink_pb2.OutputPrefixType.TINK,
                                   tink_pb2.OutputPrefixType.LEGACY,
                                   tink_pb2.OutputPrefixType.RAW,
                                   tink_pb2.OutputPrefixType.CRUNCHY]:
          yield (lang1, lang2, key, output_prefix_type)


def invalid_lang_and_key():
  for lang in tink_config.supported_languages_for_key_type('HmacKey'):
    for key in invalid_keys():
      yield (lang, key)


class HmacKeyTest(parameterized.TestCase):
  """Tests specific for keys of type HmacKey."""

  @parameterized.parameters(valid_lang_and_key())
  def test_create_mac(
      self, lang: str, key: hmac_pb2.HmacKey
  ):
    keyset = to_keyset(key, tink_pb2.OutputPrefixType.TINK)
    testing_servers.remote_primitive(
        lang, keyset.SerializeToString(), tink.mac.Mac
    )

  @parameterized.parameters(consistency_test_cases())
  def test_compute_mac_lang1_lang2(
      self,
      lang1: str,
      lang2: str,
      key: hmac_pb2.HmacKey,
      output_prefix_type: tink_pb2.OutputPrefixType,
  ):
    keyset = to_keyset(key, output_prefix_type)
    mac1 = testing_servers.remote_primitive(
        lang1, keyset.SerializeToString(), tink.mac.Mac
    )
    mac2 = testing_servers.remote_primitive(
        lang2, keyset.SerializeToString(), tink.mac.Mac
    )
    message = os.urandom(random.choice([0, 1, 17, 31, 1027]))
    mac2.verify_mac(mac1.compute_mac(message), message)


if __name__ == '__main__':
  absltest.main()
