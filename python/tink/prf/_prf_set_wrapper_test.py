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

"""Tests for tink.python.tink.aead_wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
import tink
from tink import prf
from tink.testing import keyset_builder


TEMPLATE = prf.prf_key_templates.HMAC_SHA256


def setUpModule():
  prf.register()


class PrfSetWrapperTest(absltest.TestCase):

  def test_wrapped_output_is_equal(self):
    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(prf.PrfSet)
    output = primitive.primary().compute(b'input', output_length=31)
    key_id = primitive.primary_id()
    prfs = primitive.all()
    self.assertLen(prfs, 1)
    self.assertEqual(prfs[key_id].compute(b'input', output_length=31), output)

  def test_invalid_length_fails(self):
    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(prf.PrfSet)
    with self.assertRaises(tink.TinkError):
      _ = primitive.primary().compute(b'input', output_length=1234567)
    prfs = primitive.all()
    self.assertLen(prfs, 1)
    with self.assertRaises(tink.TinkError):
      _ = prfs[primitive.primary_id()].compute(b'input', output_length=1234567)

  def test_wrap_three_with_one_disabled(self):
    builder = keyset_builder.new_keyset_builder()
    id1 = builder.add_new_key(TEMPLATE)
    id2 = builder.add_new_key(TEMPLATE)
    disabled_id = builder.add_new_key(TEMPLATE)
    builder.disable_key(disabled_id)
    builder.set_primary_key(id1)
    prf_set1 = builder.keyset_handle().primitive(prf.PrfSet)
    builder.set_primary_key(id2)
    prf_set2 = builder.keyset_handle().primitive(prf.PrfSet)
    self.assertNotEqual(id1, id2)
    self.assertEqual(prf_set1.primary_id(), id1)
    self.assertEqual(prf_set2.primary_id(), id2)

    output1 = prf_set1.primary().compute(b'input', output_length=31)
    output2 = prf_set2.primary().compute(b'input', output_length=31)
    self.assertNotEqual(output1, output2)
    prfs = prf_set1.all()
    self.assertLen(prfs, 2)
    self.assertEqual(prfs[id1].compute(b'input', output_length=31),
                     output1)
    self.assertEqual(prfs[id2].compute(b'input', output_length=31),
                     output2)


if __name__ == '__main__':
  absltest.main()
