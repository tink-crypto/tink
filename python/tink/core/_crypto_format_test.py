# Copyright 2019 Google LLC.
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

"""Tests for tink.python.tink.crypto_format."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import core


def to_byte(c):
  # items in byte strings are of type str in Python v2.7 and int in v3.5
  if isinstance(c, str):
    return c.encode()
  else:
    return chr(c).encode()


class CryptoFormatTest(absltest.TestCase):

  def test_tink_prefix(self):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.TINK
    key.key_id = 0x00040695
    prefix = core.crypto_format.output_prefix(key)
    self.assertLen(prefix, core.crypto_format.TINK_PREFIX_SIZE)
    self.assertEqual(
        to_byte(prefix[0]), bytes(core.crypto_format.TINK_START_BYTE))
    # key_id in big-endian format.
    self.assertEqual(prefix[1:5], b'\x00\x04\x06\x95')

  def test_legacy_prefix(self):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.LEGACY
    key.key_id = 0xFF7F1058
    prefix = core.crypto_format.output_prefix(key)
    self.assertLen(prefix, core.crypto_format.NON_RAW_PREFIX_SIZE)
    self.assertEqual(to_byte(prefix[0]), core.crypto_format.LEGACY_START_BYTE)
    # key_id in big-endian format.
    self.assertEqual(prefix[1:5], b'\xFF\x7F\x10\x58')

  def test_crunchy_prefix(self):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.CRUNCHY
    key.key_id = 0x12AAB1
    prefix = core.crypto_format.output_prefix(key)
    self.assertLen(prefix, core.crypto_format.NON_RAW_PREFIX_SIZE)
    self.assertEqual(to_byte(prefix[0]), core.crypto_format.LEGACY_START_BYTE)
    # key_id in big-endian format.
    self.assertEqual(prefix[1:5], b'\x00\x12\xAA\xB1')

  def test_raw_prefix(self):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.RAW
    key.key_id = 0x74EB33
    prefix = core.crypto_format.output_prefix(key)
    self.assertLen(prefix, core.crypto_format.RAW_PREFIX_SIZE)

  def test_invalid_output_prefix(self):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = 42
    key.key_id = 0x11223344
    with self.assertRaises(core.TinkError):
      _ = core.crypto_format.output_prefix(key)


if __name__ == '__main__':
  absltest.main()
