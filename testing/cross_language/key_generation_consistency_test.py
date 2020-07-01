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
"""Tests for tink.testing.cross_language.key_generation_consistency."""

import itertools

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac

from tink.proto import common_pb2
from util import supported_key_types
from util import testing_servers

TYPE_URL_TO_SUPPORTED_LANGUAGES = {
    'type.googleapis.com/google.crypto.tink.' + key_type: langs
    for key_type, langs in supported_key_types.SUPPORTED_LANGUAGES.items()
}

# Test cases that succeed in a language but should fail
SUCCEEDS_BUT_SHOULD_FAIL = [
    # TODO(b/159989251)
    # HMAC with SHA384 is accepted in go, but not in other langs.
    ('HmacKey(32,10,SHA384)', 'go'),
    ('HmacKey(32,16,SHA384)', 'go'),
    ('HmacKey(32,20,SHA384)', 'go'),
    ('HmacKey(32,21,SHA384)', 'go'),
    ('HmacKey(32,24,SHA384)', 'go'),
    ('HmacKey(32,32,SHA384)', 'go'),
    ('HmacKey(32,33,SHA384)', 'go'),
    # TODO(b/160130470): In CC and Python Hybrid templates are not checked for
    # valid AEAD params. (These params *are* checked when the key is used.)
    ('EciesAeadHkdfPrivateKey(NIST_P256,UNCOMPRESSED,SHA256,AesEaxKey(15,11))',
     'cc'),
    ('EciesAeadHkdfPrivateKey(NIST_P256,UNCOMPRESSED,SHA256,AesEaxKey(15,11))',
     'python')
]

# Test cases that fail in a language but should succeed
FAILS_BUT_SHOULD_SUCCEED = [
    # TODO(b/160134058) Java and Go do not accept templates with CURVE25519.
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA1,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA1,AesGcmKey(16))',
     'go'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA256,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA256,AesGcmKey(16))',
     'go'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA384,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA384,AesGcmKey(16))',
     'go'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA512,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA512,AesGcmKey(16))',
     'go'),
    # TODO(b/160132617) Java does not accept templates with hash type SHA384.
    ('EciesAeadHkdfPrivateKey(NIST_P256,UNCOMPRESSED,SHA384,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(NIST_P384,UNCOMPRESSED,SHA384,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(NIST_P521,UNCOMPRESSED,SHA384,AesGcmKey(16))',
     'java'),
]

HASH_TYPES = [
    common_pb2.UNKNOWN_HASH,
    common_pb2.SHA1,
    common_pb2.SHA256,
    common_pb2.SHA384,
    common_pb2.SHA512
]

CURVE_TYPES = [
    common_pb2.UNKNOWN_CURVE,
    common_pb2.NIST_P256,
    common_pb2.NIST_P384,
    common_pb2.NIST_P521,
    common_pb2.CURVE25519
]

EC_POINT_FORMATS = [
    common_pb2.UNKNOWN_FORMAT,
    common_pb2.UNCOMPRESSED,
    common_pb2.COMPRESSED,
    common_pb2.DO_NOT_USE_CRUNCHY_UNCOMPRESSED
]


def aes_eax_test_cases():
  for key_size in [15, 16, 24, 32, 64, 96]:
    for iv_size in [11, 12, 16, 17, 24, 32]:
      yield ('AesEaxKey(%d,%d)' % (key_size, iv_size),
             aead.aead_key_templates.create_aes_eax_key_template(
                 key_size, iv_size))


def aes_gcm_test_cases():
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield ('AesGcmKey(%d)' % key_size,
           aead.aead_key_templates.create_aes_gcm_key_template(key_size))


def aes_ctr_hmac_aead_test_cases():
  for aes_key_size in [15, 16, 24, 32, 64, 96]:
    for iv_size in [11, 12, 16, 17, 24, 32]:
      hmac_key_size = 32
      tag_size = 16
      hash_type = common_pb2.SHA256
      yield ('AesCtrHmacAeadKey(%d,%d,%d,%d,%s)' %
             (aes_key_size, iv_size, hmac_key_size, tag_size,
              common_pb2.HashType.Name(hash_type)),
             aead.aead_key_templates.create_aes_ctr_hmac_aead_key_template(
                 aes_key_size=aes_key_size,
                 iv_size=iv_size,
                 hmac_key_size=hmac_key_size,
                 tag_size=tag_size,
                 hash_type=common_pb2.SHA256))
  for hmac_key_size in [15, 16, 24, 32, 64, 96]:
    for tag_size in [9, 10, 16, 20, 21, 24, 32, 33, 64, 65]:
      for hash_type in HASH_TYPES:
        aes_key_size = 32
        iv_size = 16
        yield ('AesCtrHmacAeadKey(%d,%d,%d,%d,%s)' %
               (aes_key_size, iv_size, hmac_key_size, tag_size,
                common_pb2.HashType.Name(hash_type)),
               aead.aead_key_templates.create_aes_ctr_hmac_aead_key_template(
                   aes_key_size=aes_key_size,
                   iv_size=iv_size,
                   hmac_key_size=hmac_key_size,
                   tag_size=tag_size,
                   hash_type=hash_type))


def hmac_test_cases():
  for hmac_key_size in [15, 16, 24, 32, 64, 96]:
    tag_size = 16
    hash_type = common_pb2.SHA256
    yield ('HmacKey(%d,%d,%s)' % (hmac_key_size, tag_size,
                                  common_pb2.HashType.Name(hash_type)),
           mac.mac_key_templates.create_hmac_key_template(
               hmac_key_size, tag_size, hash_type))
  for tag_size in [9, 10, 16, 20, 21, 24, 32, 33, 64, 65]:
    for hash_type in HASH_TYPES:
      hmac_key_size = 32
      yield ('HmacKey(%d,%d,%s)' % (hmac_key_size, tag_size,
                                    common_pb2.HashType.Name(hash_type)),
             mac.mac_key_templates.create_hmac_key_template(
                 hmac_key_size, tag_size, hash_type))


def aes_siv_test_cases():
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield ('AesSivKey(%d)' % key_size,
           daead.deterministic_aead_key_templates.create_aes_siv_key_template(
               key_size))


def ecies_aead_hkdf_test_cases():
  for curve_type in CURVE_TYPES:
    for hash_type in HASH_TYPES:
      ec_point_format = common_pb2.UNCOMPRESSED
      dem_key_template = aead.aead_key_templates.AES128_GCM
      yield ('EciesAeadHkdfPrivateKey(%s,%s,%s,AesGcmKey(16))' %
             (common_pb2.EllipticCurveType.Name(curve_type),
              common_pb2.EcPointFormat.Name(ec_point_format),
              common_pb2.HashType.Name(hash_type)),
             hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
                 curve_type, ec_point_format, hash_type, dem_key_template))
  for ec_point_format in EC_POINT_FORMATS:
    curve_type = common_pb2.NIST_P256
    hash_type = common_pb2.SHA256
    dem_key_template = aead.aead_key_templates.AES128_GCM
    yield ('EciesAeadHkdfPrivateKey(%s,%s,%s,AesGcmKey(16))' %
           (common_pb2.EllipticCurveType.Name(curve_type),
            common_pb2.EcPointFormat.Name(ec_point_format),
            common_pb2.HashType.Name(hash_type)),
           hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
               curve_type, ec_point_format, hash_type, dem_key_template))
  curve_type = common_pb2.NIST_P256
  ec_point_format = common_pb2.UNCOMPRESSED
  hash_type = common_pb2.SHA256
  # Use invalid AEAD key template as DEM
  # TODO(juerg): Once b/160130470 is fixed, increase test coverage to all
  # aead templates.
  dem_key_template = aead.aead_key_templates.create_aes_eax_key_template(15, 11)
  yield ('EciesAeadHkdfPrivateKey(%s,%s,%s,AesEaxKey(15,11))' %
         (common_pb2.EllipticCurveType.Name(curve_type),
          common_pb2.EcPointFormat.Name(ec_point_format),
          common_pb2.HashType.Name(hash_type)),
         hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
             curve_type, ec_point_format, hash_type, dem_key_template))


def setUpModule():
  aead.register()
  daead.register()
  mac.register()
  hybrid.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class KeyGenerationConsistencyTest(parameterized.TestCase):

  @parameterized.parameters(
      itertools.chain(aes_eax_test_cases(),
                      aes_gcm_test_cases(),
                      aes_ctr_hmac_aead_test_cases(),
                      hmac_test_cases(),
                      aes_siv_test_cases(),
                      ecies_aead_hkdf_test_cases()))
  def test_key_generation_consistency(self, name, template):
    supported_langs = TYPE_URL_TO_SUPPORTED_LANGUAGES[template.type_url]
    failures = 0
    results = {}
    for lang in supported_langs:
      try:
        _ = testing_servers.new_keyset_handle(lang, template)
        if (name, lang) in SUCCEEDS_BUT_SHOULD_FAIL:
          failures += 1
        if (name, lang) in FAILS_BUT_SHOULD_SUCCEED:
          self.fail('(%s, %s) succeeded, but is in FAILS_BUT_SHOULD_SUCCEED' %
                    (name, lang))
        results[lang] = 'success'
      except tink.TinkError as e:
        if (name, lang) not in FAILS_BUT_SHOULD_SUCCEED:
          failures += 1
        if (name, lang) in SUCCEEDS_BUT_SHOULD_FAIL:
          self.fail(
              '(%s, %s) is in SUCCEEDS_BUT_SHOULD_FAIL, but failed with %s' %
              (name, lang, e))
        results[lang] = e
    # Test that either all supported langs accept the template, or all reject.
    if failures not in [0, len(supported_langs)]:
      self.fail('key generation for template %s is inconsistent: %s' %
                (name, results))


if __name__ == '__main__':
  absltest.main()
