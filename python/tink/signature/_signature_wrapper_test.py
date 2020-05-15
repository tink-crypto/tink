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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import tink_pb2
from tink import core
from tink import signature
from tink.testing import helper


def setUpModule():
  signature.register()


def new_sign_key_pair(key_id, output_prefix_type):
  fake_key = helper.fake_key(
      key_id=key_id,
      key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE,
      output_prefix_type=output_prefix_type)
  fake_sign = helper.FakePublicKeySign('fakePublicKeySign {}'.format(key_id))
  return fake_sign, fake_key


def to_verify_key_pair(key):
  fake_verify = helper.FakePublicKeyVerify('fakePublicKeySign {}'.format(
      key.key_id))
  return fake_verify, key


class PublicKeySignWrapperTest(parameterized.TestCase):

  @parameterized.named_parameters(('tink', tink_pb2.TINK),
                                  ('legacy', tink_pb2.LEGACY))
  def test_signature(self, output_prefix_type):
    pair0 = new_sign_key_pair(1234, output_prefix_type)
    pair1 = new_sign_key_pair(5678, output_prefix_type)
    pset = core.new_primitive_set(signature.PublicKeySign)
    pset_verify = core.new_primitive_set(signature.PublicKeyVerify)

    pset.add_primitive(*pair0)
    pset.set_primary(pset.add_primitive(*pair1))

    pset_verify.add_primitive(*to_verify_key_pair(pair0[1]))
    entry = pset_verify.add_primitive(*to_verify_key_pair(pair1[1]))
    pset_verify.set_primary(entry)

    wrapped_pk_sign = core.Registry.wrap(pset)
    wrapped_pk_verify = core.Registry.wrap(pset_verify)
    data_signature = wrapped_pk_sign.sign(b'data')

    wrapped_pk_verify.verify(data_signature, b'data')

    with self.assertRaisesRegex(core.TinkError, 'invalid signature'):
      wrapped_pk_verify.verify(data_signature, b'invalid')


def new_verify_key_pair(key_id, output_prefix_type):
  fake_key = helper.fake_key(
      key_id=key_id,
      key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE,
      output_prefix_type=output_prefix_type)
  fake_verify = helper.FakePublicKeyVerify(
      'fakePublicKeySign {}'.format(key_id))
  return fake_verify, fake_key,


class PublicKeyVerifyWrapperTest(absltest.TestCase):

  def test_verify_signature(self):
    pair0 = new_verify_key_pair(1234, tink_pb2.RAW)
    pair1 = new_verify_key_pair(5678, tink_pb2.TINK)
    pair2 = new_verify_key_pair(9012, tink_pb2.LEGACY)
    pset = core.new_primitive_set(signature.PublicKeyVerify)

    pset.add_primitive(*pair0)
    pset.add_primitive(*pair1)
    pset.set_primary(pset.add_primitive(*pair2))

    # Check all keys work
    for unused_primitive, key in (pair0, pair1, pair2):
      pset_sign = core.new_primitive_set(signature.PublicKeySign)
      pset_sign.set_primary(
          pset_sign.add_primitive(
              helper.FakePublicKeySign('fakePublicKeySign {}'.format(
                  key.key_id)), key))

      wrapped_pk_verify = core.Registry.wrap(pset)
      wrapped_pk_sign = core.Registry.wrap(pset_sign)

      wrapped_pk_verify.verify(wrapped_pk_sign.sign(b'data'), b'data')

if __name__ == '__main__':
  absltest.main()
