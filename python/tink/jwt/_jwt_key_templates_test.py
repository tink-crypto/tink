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
"""Tests for tink.python.tink.jwt._jwt_key_templates."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import jwt
from tink.testing import helper


def setUpModule():
  jwt.register_jwt_mac()
  jwt.register_jwt_signature()


class JwtKeyTemplatesTest(parameterized.TestCase):

  @parameterized.parameters([
      ('JWT_HS256', jwt.jwt_hs256_template()),
      ('JWT_HS256_RAW', jwt.raw_jwt_hs256_template()),
      ('JWT_HS384', jwt.jwt_hs384_template()),
      ('JWT_HS384_RAW', jwt.raw_jwt_hs384_template()),
      ('JWT_HS512', jwt.jwt_hs512_template()),
      ('JWT_HS512_RAW', jwt.raw_jwt_hs512_template()),
      ('JWT_ES256', jwt.jwt_es256_template()),
      ('JWT_ES256_RAW', jwt.raw_jwt_es256_template()),
      ('JWT_ES384', jwt.jwt_es384_template()),
      ('JWT_ES384_RAW', jwt.raw_jwt_es384_template()),
      ('JWT_ES512', jwt.jwt_es512_template()),
      ('JWT_ES512_RAW', jwt.raw_jwt_es512_template()),
      ('JWT_RS256_2048_F4', jwt.jwt_rs256_2048_f4_template()),
      ('JWT_RS256_2048_F4_RAW', jwt.raw_jwt_rs256_2048_f4_template()),
      ('JWT_RS256_3072_F4', jwt.jwt_rs256_3072_f4_template()),
      ('JWT_RS256_3072_F4_RAW', jwt.raw_jwt_rs256_3072_f4_template()),
      ('JWT_RS384_3072_F4', jwt.jwt_rs384_3072_f4_template()),
      ('JWT_RS384_3072_F4_RAW', jwt.raw_jwt_rs384_3072_f4_template()),
      ('JWT_RS512_4096_F4', jwt.jwt_rs512_4096_f4_template()),
      ('JWT_RS512_4096_F4_RAW', jwt.raw_jwt_rs512_4096_f4_template()),
      ('JWT_PS256_2048_F4', jwt.jwt_ps256_2048_f4_template()),
      ('JWT_PS256_2048_F4_RAW', jwt.raw_jwt_ps256_2048_f4_template()),
      ('JWT_PS256_3072_F4', jwt.jwt_ps256_3072_f4_template()),
      ('JWT_PS256_3072_F4_RAW', jwt.raw_jwt_ps256_3072_f4_template()),
      ('JWT_PS384_3072_F4', jwt.jwt_ps384_3072_f4_template()),
      ('JWT_PS384_3072_F4_RAW', jwt.raw_jwt_ps384_3072_f4_template()),
      ('JWT_PS512_4096_F4', jwt.jwt_ps512_4096_f4_template()),
      ('JWT_PS512_4096_F4_RAW', jwt.raw_jwt_ps512_4096_f4_template()),
  ])
  def test_template(self, template_name, template):
    self.assertEqual(template,
                     helper.template_from_testdata(template_name, 'jwt'))

  @parameterized.named_parameters(('0', 0, b'\x00'), ('256', 256, b'\x01\x00'),
                                  ('65537', 65537, b'\x01\x00\x01'))
  def test_num_to_bytes(self, number, expected):
    self.assertEqual(jwt._jwt_key_templates._num_to_bytes(number),
                     expected)

  @parameterized.named_parameters([
      ('JWT_HS256', jwt.jwt_hs256_template()),
      ('JWT_HS256_RAW', jwt.raw_jwt_hs256_template()),
      ('JWT_HS384', jwt.jwt_hs384_template()),
      ('JWT_HS384_RAW', jwt.raw_jwt_hs384_template()),
      ('JWT_HS512', jwt.jwt_hs512_template()),
      ('JWT_HS512_RAW', jwt.raw_jwt_hs512_template()),
  ])
  def test_mac_success(self, key_template):
    keyset_handle = tink.new_keyset_handle(key_template)
    jwt_hmac = keyset_handle.primitive(jwt.JwtMac)
    token = jwt.new_raw_jwt(
        issuer='issuer', subject='subject', without_expiration=True)
    compact = jwt_hmac.compute_mac_and_encode(token)
    output_token = jwt_hmac.verify_mac_and_decode(
        compact,
        jwt.new_validator(
            expected_issuer='issuer',
            expected_subject='subject',
            allow_missing_expiration=True))
    self.assertEqual(output_token.issuer(), token.issuer())
    self.assertEqual(output_token.subject(), token.subject())

  @parameterized.named_parameters([
      ('JWT_ES256', jwt.jwt_es256_template()),
      ('JWT_ES256_RAW', jwt.raw_jwt_es256_template()),
      ('JWT_ES384', jwt.jwt_es384_template()),
      ('JWT_ES384_RAW', jwt.raw_jwt_es384_template()),
      ('JWT_ES512', jwt.jwt_es512_template()),
      ('JWT_ES512_RAW', jwt.raw_jwt_es512_template()),
      ('JWT_RS256_2048_F4', jwt.jwt_rs256_2048_f4_template()),
      ('JWT_RS256_2048_F4_RAW', jwt.raw_jwt_rs256_2048_f4_template()),
      ('JWT_RS256_3072_F4', jwt.jwt_rs256_3072_f4_template()),
      ('JWT_RS256_3072_F4_RAW', jwt.raw_jwt_rs256_3072_f4_template()),
      ('JWT_RS384_3072_F4', jwt.jwt_rs384_3072_f4_template()),
      ('JWT_RS384_3072_F4_RAW', jwt.raw_jwt_rs384_3072_f4_template()),
      ('JWT_RS512_4096_F4', jwt.jwt_rs512_4096_f4_template()),
      ('JWT_RS512_4096_F4_RAW', jwt.raw_jwt_rs512_4096_f4_template()),
      ('JWT_PS256_2048_F4', jwt.jwt_ps256_2048_f4_template()),
      ('JWT_PS256_2048_F4_RAW', jwt.raw_jwt_ps256_2048_f4_template()),
      ('JWT_PS256_3072_F4', jwt.jwt_ps256_3072_f4_template()),
      ('JWT_PS256_3072_F4_RAW', jwt.raw_jwt_ps256_3072_f4_template()),
      ('JWT_PS384_3072_F4', jwt.jwt_ps384_3072_f4_template()),
      ('JWT_PS384_3072_F4_RAW', jwt.raw_jwt_ps384_3072_f4_template()),
      ('JWT_PS512_4096_F4', jwt.jwt_ps512_4096_f4_template()),
      ('JWT_PS512_4096_F4_RAW', jwt.raw_jwt_ps512_4096_f4_template()),
  ])
  def test_new_keydata_primitive_success(self, template):
    private_handle = tink.new_keyset_handle(template)
    sign = private_handle.primitive(jwt.JwtPublicKeySign)
    verify = private_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer', subject='subject', without_expiration=True)
    compact = sign.sign_and_encode(raw_jwt)
    verified_jwt = verify.verify_and_decode(
        compact,
        jwt.new_validator(
            expected_issuer='issuer',
            expected_subject='subject',
            allow_missing_expiration=True))
    self.assertEqual(verified_jwt.issuer(), 'issuer')
    self.assertEqual(verified_jwt.subject(), 'subject')

if __name__ == '__main__':
  absltest.main()
