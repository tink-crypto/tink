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

"""Tests for tink.python.tink.signature_key_templates."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized
from tink import signature


def bytes_to_num(data):
  res = 0

  for b in bytearray(data):
    res <<= 8
    res |= b

  return res


def setUpModule():
  signature.register()


class SignatureKeyTemplatesTest(parameterized.TestCase):

  def test_bytes_to_num(self):
    for i in range(100000):
      res = bytes_to_num(signature.signature_key_templates._num_to_bytes(i))
      self.assertEqual(res, i)

  @parameterized.named_parameters(('0', 0, b'\x00'), ('256', 256, b'\x01\x00'),
                                  ('65537', 65537, b'\x01\x00\x01'))
  def test_num_to_bytes(self, number, expected):
    self.assertEqual(signature.signature_key_templates._num_to_bytes(number),
                     expected)

  def test_num_to_bytes_minus_one_overflow(self):
    with self.assertRaises(OverflowError):
      signature.signature_key_templates._num_to_bytes(-1)


if __name__ == '__main__':
  absltest.main()
