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
"""Tests for big_integer_util."""

from absl.testing import absltest
from absl.testing import parameterized

from tink.internal import big_integer_util


class BigIntegerUtilTest(parameterized.TestCase):

  def test_bytes_to_num(self):
    for i in range(100000):
      big_int_bytes = big_integer_util.num_to_bytes(i)
      self.assertEqual(int.from_bytes(big_int_bytes, byteorder='big'), i)

  @parameterized.named_parameters(
      ('0', 0, b'\x00'), ('255', 255, b'\xff'), ('256', 256, b'\x01\x00'),
      ('65535', 65535, b'\xff\xff'), ('65536', 65536, b'\x01\x00\x00'),
      ('65537', 65537, b'\x01\x00\x01'), ('65538', 65538, b'\x01\x00\x02'),
      ('16909060', 16909060, b'\x01\x02\x03\x04'))
  def test_num_to_bytes(self, number, expected):
    self.assertEqual(big_integer_util.num_to_bytes(number), expected)

  def test_num_to_bytes_minus_one_overflow(self):
    with self.assertRaises(OverflowError):
      big_integer_util.num_to_bytes(-1)


if __name__ == '__main__':
  absltest.main()
