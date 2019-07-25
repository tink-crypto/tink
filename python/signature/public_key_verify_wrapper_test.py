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

"""Tests for tink.python.public_key_verify_wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest

from tink.proto import tink_pb2
from tink.python.core import primitive_set
from tink.python.signature import public_key_sign
from tink.python.signature import public_key_sign_wrapper
from tink.python.signature import public_key_verify
from tink.python.signature import public_key_verify_wrapper
from tink.python.testing import helper


def new_primitive_key_pair(key_id, output_prefix_type):
  fake_key = helper.fake_key(
      key_id=key_id,
      key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE,
      output_prefix_type=output_prefix_type)
  fake_sign = helper.FakePublicKeyVerify('fakePublicKeySign {}'.format(key_id))
  return fake_sign, fake_key,


class PublicKeyVerifyWrapperTest(absltest.TestCase):

  def test_verify_signature(self):
    pair0 = new_primitive_key_pair(1234, tink_pb2.RAW)
    pair1 = new_primitive_key_pair(5678, tink_pb2.TINK)
    pair2 = new_primitive_key_pair(9012, tink_pb2.LEGACY)
    pset = primitive_set.new_primitive_set(public_key_verify.PublicKeyVerify)

    pset.add_primitive(*pair0)
    pset.add_primitive(*pair1)
    pset.set_primary(pset.add_primitive(*pair2))

    # Check all keys work
    for unused_primitive, key in (pair0, pair1, pair2):
      pset_sign = primitive_set.new_primitive_set(public_key_sign.PublicKeySign)
      pset_sign.set_primary(
          pset_sign.add_primitive(
              helper.FakePublicKeySign('fakePublicKeySign {}'.format(
                  key.key_id)), key))

      wrapped_pk_verify = public_key_verify_wrapper.PublicKeyVerifyWrapper(
      ).wrap(pset)
      wrapped_pk_sign = public_key_sign_wrapper.PublicKeySignWrapper().wrap(
          pset_sign)

      wrapped_pk_verify.verify(wrapped_pk_sign.sign(b'data'), b'data')


if __name__ == '__main__':
  absltest.main()
