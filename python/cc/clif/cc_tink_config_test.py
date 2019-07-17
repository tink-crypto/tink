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

"""Tests for tink.python.cc.clif.cc_tink_config."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import unittest
from tink.python.cc.clif import cc_tink_config


class CcTinkConfigTest(unittest.TestCase):

  def test_latest(self):
    cc_tink_config.register()
    latest = cc_tink_config.latest()
    primitive_names = {entry.primitive_name for entry in latest.entry}
    self.assertIn('Aead', primitive_names)
    self.assertIn('Mac', primitive_names)
    self.assertIn('PublicKeySign', primitive_names)
    type_urls = {entry.type_url for entry in latest.entry}
    self.assertIn('type.googleapis.com/google.crypto.tink.AesEaxKey', type_urls)
    self.assertIn('type.googleapis.com/google.crypto.tink.AesGcmKey', type_urls)
    self.assertIn('type.googleapis.com/google.crypto.tink.HmacKey', type_urls)
    self.assertIn('type.googleapis.com/google.crypto.tink.EcdsaPrivateKey',
                  type_urls)


if __name__ == '__main__':
  googletest.main()
