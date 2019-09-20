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
"""Tests for tink.python.core.cleartext_keyset_handle."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io

from absl.testing import absltest

from tink.python import core
from tink.python import mac
from tink.python import tink_config
from tink.python.core import cleartext_keyset_handle


def setUpModule():
  tink_config.register()


class CleartextKeysetHandleTest(absltest.TestCase):

  def test_write(self):
    handle = cleartext_keyset_handle.CleartextKeysetHandle.generate_new(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    output_stream = io.BytesIO()
    writer = core.BinaryKeysetWriter(output_stream)
    handle.write(writer)
    reader = core.BinaryKeysetReader(output_stream.getvalue())
    handle2 = cleartext_keyset_handle.CleartextKeysetHandle.read(reader)
    # Check that handle2 has the same primitive as handle.
    handle2.primitive(mac.Mac).verify_mac(
        handle.primitive(mac.Mac).compute_mac(b'data'), b'data')

  def test_read_empty_keyset_fails(self):
    with self.assertRaisesRegex(core.TinkError, 'No keyset found'):
      cleartext_keyset_handle.CleartextKeysetHandle.read(
          core.BinaryKeysetReader(b''))


if __name__ == '__main__':
  absltest.main()
