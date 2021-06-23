# Copyright 2021 Google LLC
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
"""Tests for tink.python.tink.jwt._jwt_signature_wrappers_test."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import jwt
from tink.testing import keyset_builder


def setUpModule():
  jwt.register_jwt_signature()


class JwtSignatureWrapperTest(parameterized.TestCase):

  def test_interesting_error(self):
    private_handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    sign = private_handle.primitive(jwt.JwtPublicKeySign)
    verify = private_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    compact = sign.sign_and_encode(raw_jwt)
    with self.assertRaisesRegex(jwt.JwtInvalidError,
                                'invalid JWT; expected issuer'):
      verify.verify_and_decode(compact, jwt.new_validator(
          expected_issuer='unknown', allow_missing_expiration=True))

  def test_key_rotation(self):
    old_key_tmpl = jwt.jwt_es256_template()
    new_key_tmpl = jwt.jwt_es384_template()
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)

    builder.set_primary_key(older_key_id)
    handle1 = builder.keyset_handle()
    sign1 = handle1.primitive(jwt.JwtPublicKeySign)
    verify1 = handle1.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    newer_key_id = builder.add_new_key(new_key_tmpl)
    handle2 = builder.keyset_handle()
    sign2 = handle2.primitive(jwt.JwtPublicKeySign)
    verify2 = handle2.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    builder.set_primary_key(newer_key_id)
    handle3 = builder.keyset_handle()
    sign3 = handle3.primitive(jwt.JwtPublicKeySign)
    verify3 = handle3.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    builder.disable_key(older_key_id)
    handle4 = builder.keyset_handle()
    sign4 = handle4.primitive(jwt.JwtPublicKeySign)
    verify4 = handle4.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    raw_jwt = jwt.new_raw_jwt(issuer='a', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='a', allow_missing_expiration=True)

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 uses the older key. So 1, 2 and 3 can verify the signature, but not 4.
    compact1 = sign1.sign_and_encode(raw_jwt)
    self.assertEqual(
        verify1.verify_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        verify2.verify_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact1, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      verify4.verify_and_decode(compact1, validator)

    # 2 uses the older key. So 1, 2 and 3 can verify the signature, but not 4.
    compact2 = sign2.sign_and_encode(raw_jwt)
    self.assertEqual(
        verify1.verify_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        verify2.verify_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact2, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      verify4.verify_and_decode(compact2, validator)

    # 3 uses the newer key. So 2, 3 and 4 can verify the signature, but not 1.
    compact3 = sign3.sign_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      verify1.verify_and_decode(compact3, validator)
    self.assertEqual(
        verify2.verify_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        verify4.verify_and_decode(compact3, validator).issuer(), 'a')

    # 4 uses the newer key. So 2, 3 and 4 can verify the signature, but not 1.
    compact4 = sign4.sign_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      verify1.verify_and_decode(compact4, validator)
    self.assertEqual(
        verify2.verify_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        verify4.verify_and_decode(compact4, validator).issuer(), 'a')


if __name__ == '__main__':
  absltest.main()
