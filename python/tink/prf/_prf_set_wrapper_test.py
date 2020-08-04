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

"""Tests for tink.python.tink.aead_wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import core
from tink import prf
from tink.prf import _prf_set_wrapper
from tink.testing import helper


def setUpModule():
  core.Registry.register_primitive_wrapper(_prf_set_wrapper.PrfSetWrapper())


class PrfSetWrapperTest(absltest.TestCase):

  def new_primitive_key_pair(self, key_id):
    fake_key = helper.fake_key(key_id=key_id, output_prefix_type=tink_pb2.RAW)
    fake_prf_set = helper.FakePrfSet('fakePrfSet {}'.format(key_id))
    return fake_prf_set, fake_key

  def test_wrap_one(self):
    primitive, key = self.new_primitive_key_pair(1234)
    pset = core.new_primitive_set(prf.PrfSet)
    entry = pset.add_primitive(primitive, key)
    pset.set_primary(entry)
    wrapped_prf_set = core.Registry.wrap(pset)
    expected_output = primitive.primary().compute(b'input', output_length=31)

    self.assertEqual(
        wrapped_prf_set.primary().compute(b'input', output_length=31),
        expected_output)
    self.assertEqual(wrapped_prf_set.primary_id(), 1234)
    prfs = wrapped_prf_set.all()
    self.assertLen(prfs, 1)
    self.assertEqual(prfs[1234].compute(b'input', output_length=31),
                     expected_output)

  def test_wrap_two(self):
    primitive1, key1 = self.new_primitive_key_pair(1234)
    primitive2, key2 = self.new_primitive_key_pair(5678)
    pset = core.new_primitive_set(prf.PrfSet)
    _ = pset.add_primitive(primitive1, key1)
    entry2 = pset.add_primitive(primitive2, key2)
    pset.set_primary(entry2)
    wrapped_prf_set = core.Registry.wrap(pset)
    expected_output1 = primitive1.primary().compute(b'input', output_length=31)
    expected_output2 = primitive2.primary().compute(b'input', output_length=31)

    self.assertEqual(
        wrapped_prf_set.primary().compute(b'input', output_length=31),
        expected_output2)
    self.assertEqual(wrapped_prf_set.primary_id(), 5678)
    prfs = wrapped_prf_set.all()
    self.assertLen(prfs, 2)
    self.assertEqual(prfs[1234].compute(b'input', output_length=31),
                     expected_output1)
    self.assertEqual(prfs[5678].compute(b'input', output_length=31),
                     expected_output2)

  def test_invalid_length_fails(self):
    primitive, key = self.new_primitive_key_pair(1234)
    pset = core.new_primitive_set(prf.PrfSet)
    entry = pset.add_primitive(primitive, key)
    pset.set_primary(entry)
    wrapped_prf_set = core.Registry.wrap(pset)

    with self.assertRaises(core.TinkError):
      _ = wrapped_prf_set.primary().compute(b'input', output_length=1234567)
    with self.assertRaises(core.TinkError):
      _ = wrapped_prf_set.all()[1234].compute(b'input', output_length=1234567)


if __name__ == '__main__':
  absltest.main()
