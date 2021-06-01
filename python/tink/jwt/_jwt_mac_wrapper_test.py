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
"""Tests for tink.python.tink.jwt._jwt_mac_wrapper."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import jwt
from tink.testing import keyset_builder


def setUpModule():
  jwt.register_jwt_mac()


class JwtHmacKeyManagerTest(parameterized.TestCase):

  def test_key_rotation(self):
    old_key_tmpl = jwt.jwt_hs256_template()
    new_key_tmpl = jwt.jwt_hs384_template()
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)

    builder.set_primary_key(older_key_id)
    jwtmac1 = builder.keyset_handle().primitive(jwt.JwtMac)

    newer_key_id = builder.add_new_key(new_key_tmpl)
    jwtmac2 = builder.keyset_handle().primitive(jwt.JwtMac)

    builder.set_primary_key(newer_key_id)
    jwtmac3 = builder.keyset_handle().primitive(jwt.JwtMac)

    builder.disable_key(older_key_id)
    jwtmac4 = builder.keyset_handle().primitive(jwt.JwtMac)

    raw_jwt = jwt.new_raw_jwt(issuer='a')
    validator = jwt.new_validator(expected_issuer='a')

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    compact1 = jwtmac1.compute_mac_and_encode(raw_jwt)
    self.assertEqual(
        jwtmac1.verify_mac_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact1, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      jwtmac4.verify_mac_and_decode(compact1, validator)

    # 2 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    compact2 = jwtmac2.compute_mac_and_encode(raw_jwt)
    self.assertEqual(
        jwtmac1.verify_mac_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact2, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      jwtmac4.verify_mac_and_decode(compact2, validator)

    # 3 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    compact3 = jwtmac3.compute_mac_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      jwtmac1.verify_mac_and_decode(compact3, validator)
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac4.verify_mac_and_decode(compact3, validator).issuer(), 'a')

    # 4 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    compact4 = jwtmac4.compute_mac_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      jwtmac1.verify_mac_and_decode(compact4, validator)
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac4.verify_mac_and_decode(compact4, validator).issuer(), 'a')


if __name__ == '__main__':
  absltest.main()
