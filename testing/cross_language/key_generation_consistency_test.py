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
"""Tests that keys are consistently accepted or rejected in all languages."""

import itertools
from typing import Iterable, Tuple

from absl import logging
from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
from util import supported_key_types
from util import testing_servers

# Test cases that succeed in a language but should fail
SUCCEEDS_BUT_SHOULD_FAIL = [
    # TODO(b/160130470): In CC and Python Hybrid templates are not checked for
    # valid AEAD params. (These params *are* checked when the key is used.)
    ('EciesAeadHkdfPrivateKey(NIST_P256,UNCOMPRESSED,SHA256,AesEaxKey(15,11))',
     'cc'),
    ('EciesAeadHkdfPrivateKey(NIST_P256,UNCOMPRESSED,SHA256,AesEaxKey(15,11))',
     'python'),
    # TODO(b/232503130): Add stricter JwtHmacKey validation.
    ('JwtHmacKey(47,HS384,RAW)', 'go'),
    ('JwtHmacKey(63,HS512,RAW)', 'go'),
]

# Test cases that fail in a language but should succeed
FAILS_BUT_SHOULD_SUCCEED = [
    # TODO(b/160134058) Java and Go do not accept templates with CURVE25519.
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA1,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA1,AesGcmKey(16))',
     'go'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA224,AesGcmKey(16))',
     'java'),
    ('EciesAeadHkdfPrivateKey(CURVE25519,UNCOMPRESSED,SHA224,AesGcmKey(16))',
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
]

HASH_TYPES = [
    common_pb2.UNKNOWN_HASH, common_pb2.SHA1, common_pb2.SHA224,
    common_pb2.SHA256, common_pb2.SHA384, common_pb2.SHA512
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

SIGNATURE_ENCODINGS = [
    ecdsa_pb2.UNKNOWN_ENCODING,
    ecdsa_pb2.IEEE_P1363,
    ecdsa_pb2.DER
]


TestCasesType = Iterable[Tuple[str, tink_pb2.KeyTemplate]]


def aes_eax_test_cases() -> TestCasesType:
  for key_size in [15, 16, 24, 32, 64, 96]:
    for iv_size in [11, 12, 16, 17, 24, 32]:
      yield ('AesEaxKey(%d,%d)' % (key_size, iv_size),
             aead.aead_key_templates.create_aes_eax_key_template(
                 key_size, iv_size))


def aes_gcm_test_cases() -> TestCasesType:
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield ('AesGcmKey(%d)' % key_size,
           aead.aead_key_templates.create_aes_gcm_key_template(key_size))


def aes_gcm_siv_test_cases() -> TestCasesType:
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield ('AesGcmSivKey(%d)' % key_size,
           aead.aead_key_templates.create_aes_gcm_siv_key_template(key_size))


def aes_ctr_hmac_aead_test_cases() -> TestCasesType:
  def _test_case(aes_key_size=16, iv_size=16, hmac_key_size=16,
                 tag_size=16, hash_type=common_pb2.SHA256):
    return ('AesCtrHmacAeadKey(%d,%d,%d,%d,%s)' %
            (aes_key_size, iv_size, hmac_key_size, tag_size,
             common_pb2.HashType.Name(hash_type)),
            aead.aead_key_templates.create_aes_ctr_hmac_aead_key_template(
                aes_key_size=aes_key_size,
                iv_size=iv_size,
                hmac_key_size=hmac_key_size,
                tag_size=tag_size,
                hash_type=hash_type))
  for aes_key_size in [15, 16, 24, 32, 64, 96]:
    for iv_size in [11, 12, 16, 17, 24, 32]:
      yield _test_case(aes_key_size=aes_key_size, iv_size=iv_size)
  for hmac_key_size in [15, 16, 24, 32, 64, 96]:
    for tag_size in [9, 10, 16, 20, 21, 24, 32, 33, 64, 65]:
      for hash_type in HASH_TYPES:
        yield _test_case(hmac_key_size=hmac_key_size, tag_size=tag_size,
                         hash_type=hash_type)


def hmac_test_cases() -> TestCasesType:
  def _test_case(key_size=32, tag_size=16, hash_type=common_pb2.SHA256):
    return ('HmacKey(%d,%d,%s)' % (key_size, tag_size,
                                   common_pb2.HashType.Name(hash_type)),
            mac.mac_key_templates.create_hmac_key_template(
                key_size, tag_size, hash_type))
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield _test_case(key_size=key_size)
  for tag_size in [9, 10, 16, 20, 21, 24, 32, 33, 64, 65]:
    for hash_type in HASH_TYPES:
      yield _test_case(tag_size=tag_size, hash_type=hash_type)


def jwt_hmac_test_cases() -> TestCasesType:
  def _test_case(
      algorithm: jwt_hmac_pb2.JwtHmacAlgorithm, key_size: int,
      output_prefix_type: tink_pb2.OutputPrefixType
  ) -> Tuple[str, tink_pb2.KeyTemplate]:
    key_format = jwt_hmac_pb2.JwtHmacKeyFormat(
        algorithm=algorithm, key_size=key_size)
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
        value=key_format.SerializeToString(),
        output_prefix_type=output_prefix_type)
    return ('JwtHmacKey(%d,%s,%s)' %
            (key_size, jwt_hmac_pb2.JwtHmacAlgorithm.Name(algorithm),
             tink_pb2.OutputPrefixType.Name(output_prefix_type)), template)
  yield _test_case(jwt_hmac_pb2.HS256, 31, tink_pb2.RAW)
  yield _test_case(jwt_hmac_pb2.HS256, 32, tink_pb2.RAW)
  yield _test_case(jwt_hmac_pb2.HS256, 32, tink_pb2.TINK)
  yield _test_case(jwt_hmac_pb2.HS256, 33, tink_pb2.RAW)

  yield _test_case(jwt_hmac_pb2.HS384, 47, tink_pb2.RAW)
  yield _test_case(jwt_hmac_pb2.HS384, 48, tink_pb2.RAW)
  yield _test_case(jwt_hmac_pb2.HS384, 48, tink_pb2.TINK)
  yield _test_case(jwt_hmac_pb2.HS384, 49, tink_pb2.RAW)

  yield _test_case(jwt_hmac_pb2.HS512, 63, tink_pb2.RAW)
  yield _test_case(jwt_hmac_pb2.HS512, 64, tink_pb2.RAW)
  yield _test_case(jwt_hmac_pb2.HS512, 64, tink_pb2.TINK)
  yield _test_case(jwt_hmac_pb2.HS512, 65, tink_pb2.RAW)


def aes_cmac_test_cases() -> TestCasesType:
  def _test_case(key_size=32, tag_size=16):
    return ('AesCmacKey(%d,%d)' % (key_size, tag_size),
            mac.mac_key_templates.create_aes_cmac_key_template(
                key_size, tag_size))
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield _test_case(key_size=key_size)
  for tag_size in [9, 10, 16, 20, 21, 24, 32, 33, 64, 65]:
    yield _test_case(tag_size=tag_size)


def aes_cmac_prf_test_cases() -> TestCasesType:
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield ('AesCmacPrfKey(%d)' % key_size,
           prf.prf_key_templates._create_aes_cmac_key_template(key_size))


def hmac_prf_test_cases() -> TestCasesType:
  def _test_case(key_size=32, hash_type=common_pb2.SHA256):
    return ('HmacPrfKey(%d,%s)' % (key_size,
                                   common_pb2.HashType.Name(hash_type)),
            prf.prf_key_templates._create_hmac_key_template(
                key_size, hash_type))
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield _test_case(key_size=key_size)
  for hash_type in HASH_TYPES:
    yield _test_case(hash_type=hash_type)


def hkdf_prf_test_cases() -> TestCasesType:
  def _test_case(key_size=32, hash_type=common_pb2.SHA256):
    return ('HkdfPrfKey(%d,%s)' % (key_size,
                                   common_pb2.HashType.Name(hash_type)),
            prf.prf_key_templates._create_hkdf_key_template(
                key_size, hash_type))
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield _test_case(key_size=key_size)
  for hash_type in HASH_TYPES:
    yield _test_case(hash_type=hash_type)


def aes_siv_test_cases() -> TestCasesType:
  for key_size in [15, 16, 24, 32, 64, 96]:
    yield ('AesSivKey(%d)' % key_size,
           daead.deterministic_aead_key_templates.create_aes_siv_key_template(
               key_size))


def ecies_aead_hkdf_test_cases() -> TestCasesType:
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


def ecdsa_test_cases() -> TestCasesType:
  for hash_type in HASH_TYPES:
    for curve_type in CURVE_TYPES:
      for signature_encoding in SIGNATURE_ENCODINGS:
        yield ('EcdsaPrivateKey(%s,%s,%s)' %
               (common_pb2.HashType.Name(hash_type),
                common_pb2.EllipticCurveType.Name(curve_type),
                ecdsa_pb2.EcdsaSignatureEncoding.Name(signature_encoding)),
               signature.signature_key_templates.create_ecdsa_key_template(
                   hash_type, curve_type, signature_encoding))


def rsa_ssa_pkcs1_test_cases() -> TestCasesType:
  gen = signature.signature_key_templates.create_rsa_ssa_pkcs1_key_template
  for hash_type in HASH_TYPES:
    modulus_size = 2048
    public_exponent = 65537
    yield ('RsaSsaPkcs1PrivateKey(%s,%d,%d)' %
           (common_pb2.HashType.Name(hash_type), modulus_size,
            public_exponent),
           gen(hash_type, modulus_size, public_exponent))
  for modulus_size in [0, 2000, 3072, 4096]:
    hash_type = common_pb2.SHA256
    public_exponent = 65537
    yield ('RsaSsaPkcs1PrivateKey(%s,%d,%d)' %
           (common_pb2.HashType.Name(hash_type), modulus_size,
            public_exponent),
           gen(hash_type, modulus_size, public_exponent))
  for public_exponent in [0, 1, 2, 3, 65536, 65537, 65538]:
    hash_type = common_pb2.SHA256
    modulus_size = 2048
    yield ('RsaSsaPkcs1PrivateKey(%s,%d,%d)' %
           (common_pb2.HashType.Name(hash_type), modulus_size,
            public_exponent),
           gen(hash_type, modulus_size, public_exponent))


def rsa_ssa_pss_test_cases() -> TestCasesType:
  gen = signature.signature_key_templates.create_rsa_ssa_pss_key_template
  for hash_type in HASH_TYPES:
    salt_length = 32
    modulus_size = 2048
    public_exponent = 65537
    yield ('RsaSsaPssPrivateKey(%s,%s,%d,%d,%d)' %
           (common_pb2.HashType.Name(hash_type),
            common_pb2.HashType.Name(hash_type), salt_length, modulus_size,
            public_exponent),
           gen(hash_type, hash_type, salt_length, modulus_size,
               public_exponent))
  for salt_length in [-3, 0, 1, 16, 64]:
    hash_type = common_pb2.SHA256
    modulus_size = 2048
    public_exponent = 65537
    yield ('RsaSsaPssPrivateKey(%s,%s,%d,%d,%d)' %
           (common_pb2.HashType.Name(hash_type),
            common_pb2.HashType.Name(hash_type), salt_length, modulus_size,
            public_exponent),
           gen(hash_type, hash_type, salt_length, modulus_size,
               public_exponent))
  for modulus_size in [0, 2000, 3072, 4096]:
    hash_type = common_pb2.SHA256
    salt_length = 32
    public_exponent = 65537
    yield ('RsaSsaPssPrivateKey(%s,%s,%d,%d,%d)' %
           (common_pb2.HashType.Name(hash_type),
            common_pb2.HashType.Name(hash_type), salt_length, modulus_size,
            public_exponent),
           gen(hash_type, hash_type, salt_length, modulus_size,
               public_exponent))
  hash_type1 = common_pb2.SHA256
  hash_type2 = common_pb2.SHA512
  salt_length = 32
  modulus_size = 2048
  public_exponent = 65537
  yield ('RsaSsaPssPrivateKey(%s,%s,%d,%d,%d)' %
         (common_pb2.HashType.Name(hash_type1),
          common_pb2.HashType.Name(hash_type2), salt_length, modulus_size,
          public_exponent),
         gen(hash_type1, hash_type2, salt_length, modulus_size,
             public_exponent))

  for public_exponent in [0, 1, 2, 3, 65536, 65537, 65538]:
    hash_type = common_pb2.SHA256
    salt_length = 32
    modulus_size = 2048
    yield ('RsaSsaPssPrivateKey(%s,%s,%d,%d,%d)' %
           (common_pb2.HashType.Name(hash_type),
            common_pb2.HashType.Name(hash_type), salt_length, modulus_size,
            public_exponent),
           gen(hash_type, hash_type, salt_length, modulus_size,
               public_exponent))


def setUpModule():
  aead.register()
  daead.register()
  mac.register()
  hybrid.register()
  signature.register()
  testing_servers.start('key_generation_consistency')


def tearDownModule():
  testing_servers.stop()


class KeyGenerationConsistencyTest(parameterized.TestCase):

  @parameterized.parameters(
      itertools.chain(aes_eax_test_cases(),
                      aes_gcm_test_cases(),
                      aes_gcm_siv_test_cases(),
                      aes_ctr_hmac_aead_test_cases(),
                      hmac_test_cases(),
                      jwt_hmac_test_cases(),
                      aes_cmac_test_cases(),
                      aes_cmac_prf_test_cases(),
                      hmac_prf_test_cases(),
                      hkdf_prf_test_cases(),
                      aes_siv_test_cases(),
                      ecies_aead_hkdf_test_cases(),
                      ecdsa_test_cases(),
                      rsa_ssa_pkcs1_test_cases(),
                      rsa_ssa_pss_test_cases()))
  def test_key_generation_consistency(self, name, template):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES[
        supported_key_types.KEY_TYPE_FROM_URL[template.type_url]]
    failures = 0
    results = {}
    for lang in supported_langs:
      try:
        _ = testing_servers.new_keyset(lang, template)
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
    logging.info('Key generation status: %s',
                 'Success' if failures == 0 else 'Fail')

if __name__ == '__main__':
  absltest.main()
