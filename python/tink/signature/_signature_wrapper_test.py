# Copyright 2019 Google LLC
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

"""Tests for tink.python.tink.public_key_sign_wrapper."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import signature
from tink.testing import keyset_builder


TEMPLATE = signature.signature_key_templates.ECDSA_P256
LEGACY_TEMPLATE = keyset_builder.legacy_template(TEMPLATE)
RAW_TEMPLATE = keyset_builder.raw_template(TEMPLATE)


def setUpModule():
  signature.register()


class SignatureWrapperTest(parameterized.TestCase):

  @parameterized.parameters([TEMPLATE, LEGACY_TEMPLATE, RAW_TEMPLATE])
  def test_sign_verify(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    sign_primitive = private_handle.primitive(signature.PublicKeySign)
    verify_primitive = public_handle.primitive(signature.PublicKeyVerify)

    data_signature = sign_primitive.sign(b'data')
    verify_primitive.verify(data_signature, b'data')

  @parameterized.parameters([TEMPLATE, LEGACY_TEMPLATE, RAW_TEMPLATE])
  def test_verify_fails_on_wrong_data(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    sign_primitive = private_handle.primitive(signature.PublicKeySign)
    verify_primitive = public_handle.primitive(signature.PublicKeyVerify)

    data_signature = sign_primitive.sign(b'data')
    with self.assertRaises(tink.TinkError):
      verify_primitive.verify(data_signature, b'invalid data')

  @parameterized.parameters([TEMPLATE, LEGACY_TEMPLATE, RAW_TEMPLATE])
  def test_verify_fails_on_unknown_signature(self, template):
    unknown_handle = tink.new_keyset_handle(template)
    unknown_sign_primitive = unknown_handle.primitive(signature.PublicKeySign)
    unknown_data_signature = unknown_sign_primitive.sign(b'data')

    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    verify_primitive = public_handle.primitive(signature.PublicKeyVerify)
    with self.assertRaises(tink.TinkError):
      verify_primitive.verify(unknown_data_signature, b'data')

  @parameterized.parameters([(TEMPLATE, TEMPLATE),
                             (TEMPLATE, LEGACY_TEMPLATE),
                             (TEMPLATE, RAW_TEMPLATE),
                             (LEGACY_TEMPLATE, TEMPLATE),
                             (LEGACY_TEMPLATE, LEGACY_TEMPLATE),
                             (LEGACY_TEMPLATE, RAW_TEMPLATE),
                             (RAW_TEMPLATE, TEMPLATE),
                             (RAW_TEMPLATE, LEGACY_TEMPLATE),
                             (RAW_TEMPLATE, RAW_TEMPLATE)])
  def test_sign_verify_with_key_rotation(self, old_template, new_template):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_template)
    builder.set_primary_key(older_key_id)
    private_handle1 = builder.keyset_handle()
    sign1 = private_handle1.primitive(signature.PublicKeySign)
    verify1 = private_handle1.public_keyset_handle().primitive(
        signature.PublicKeyVerify)

    newer_key_id = builder.add_new_key(new_template)
    private_handle2 = builder.keyset_handle()
    sign2 = private_handle2.primitive(signature.PublicKeySign)
    verify2 = private_handle2.public_keyset_handle().primitive(
        signature.PublicKeyVerify)

    builder.set_primary_key(newer_key_id)
    private_handle3 = builder.keyset_handle()
    sign3 = private_handle3.primitive(signature.PublicKeySign)
    verify3 = private_handle3.public_keyset_handle().primitive(
        signature.PublicKeyVerify)

    builder.disable_key(older_key_id)
    private_handle4 = builder.keyset_handle()
    sign4 = private_handle4.primitive(signature.PublicKeySign)
    verify4 = private_handle4.public_keyset_handle().primitive(
        signature.PublicKeyVerify)
    self.assertNotEqual(older_key_id, newer_key_id)

    # 1 signs with the older key. So 1, 2 and 3 can verify it, but not 4.
    data_signature1 = sign1.sign(b'data')
    verify1.verify(data_signature1, b'data')
    verify2.verify(data_signature1, b'data')
    verify3.verify(data_signature1, b'data')
    with self.assertRaises(tink.TinkError):
      verify4.verify(data_signature1, b'data')

    # 2 signs with the older key. So 1, 2 and 3 can verify it, but not 4.
    data_signature2 = sign2.sign(b'data')
    verify1.verify(data_signature2, b'data')
    verify2.verify(data_signature2, b'data')
    verify3.verify(data_signature2, b'data')
    with self.assertRaises(tink.TinkError):
      verify4.verify(data_signature2, b'data')

    # 3 signs with the newer key. So 2, 3 and 4 can verify it, but not 1.
    data_signature3 = sign3.sign(b'data')
    with self.assertRaises(tink.TinkError):
      verify1.verify(data_signature3, b'data')
    verify2.verify(data_signature3, b'data')
    verify3.verify(data_signature3, b'data')
    verify4.verify(data_signature3, b'data')

    # 4 signs with the newer key. So 2, 3 and 4 can verify it, but not 1.
    data_signature4 = sign4.sign(b'data')
    with self.assertRaises(tink.TinkError):
      verify1.verify(data_signature4, b'data')
    verify2.verify(data_signature4, b'data')
    verify3.verify(data_signature4, b'data')
    verify4.verify(data_signature4, b'data')


if __name__ == '__main__':
  absltest.main()
