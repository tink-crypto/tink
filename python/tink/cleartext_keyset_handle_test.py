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
"""Tests for tink.python.tink.cleartext_keyset_handle."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io

from absl.testing import absltest

import tink
from tink import cleartext_keyset_handle
from tink import core
from tink import mac
from tink import tink_config


def setUpModule():
  tink_config.register()


class CleartextKeysetHandleTest(absltest.TestCase):

  def test_write_read(self):
    handle = tink.new_keyset_handle(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    output_stream = io.BytesIO()
    writer = tink.BinaryKeysetWriter(output_stream)
    cleartext_keyset_handle.write(writer, handle)
    reader = tink.BinaryKeysetReader(output_stream.getvalue())
    handle2 = cleartext_keyset_handle.read(reader)
    # Check that handle2 has the same primitive as handle.
    handle2.primitive(mac.Mac).verify_mac(
        handle.primitive(mac.Mac).compute_mac(b'data'), b'data')

  def test_from_keyset(self):
    handle = tink.new_keyset_handle(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    keyset = handle._keyset
    handle2 = cleartext_keyset_handle.from_keyset(keyset)
    # Check that handle2 has the same primitive as handle.
    handle2.primitive(mac.Mac).verify_mac(
        handle.primitive(mac.Mac).compute_mac(b'data'), b'data')

  def test_read_empty_keyset_fails(self):
    with self.assertRaises(core.TinkError):
      cleartext_keyset_handle.read(tink.BinaryKeysetReader(b''))

if __name__ == '__main__':
  absltest.main()
