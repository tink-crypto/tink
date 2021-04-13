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

"""Tests for tink.python.tink.prf.prf_set_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import common_pb2
from tink.proto import hmac_prf_pb2
from tink.proto import tink_pb2
import tink
from tink import core
from tink import prf
from tink.testing import helper


def setUpModule():
  prf.register()


class PrfKeyManagerTest(parameterized.TestCase):

  @parameterized.parameters([
      ('AES_CMAC_PRF', prf.prf_key_templates.AES_CMAC),
      ('HMAC_PRF_SHA256', prf.prf_key_templates.HMAC_SHA256),
      ('HMAC_PRF_SHA512', prf.prf_key_templates.HMAC_SHA512),
      ('HKDF_PRF_SHA256', prf.prf_key_templates.HKDF_SHA256)
  ])
  def test_template(self, template_name, template):
    self.assertEqual(template,
                     helper.template_from_testdata(template_name, 'prf'))

  def test_new_key_data_success(self):
    key_template = prf.prf_key_templates._create_hmac_key_template(
        key_size=32, hash_type=common_pb2.SHA256)
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_data = key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = hmac_prf_pb2.HmacPrfKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.hash, common_pb2.SHA256)
    self.assertLen(key.key_value, 32)

  def test_invalid_params_throw_exception(self):
    template = prf.prf_key_templates._create_hmac_key_template(
        key_size=7, hash_type=common_pb2.SHA256)
    with self.assertRaises(tink.TinkError):
      tink.new_keyset_handle(template)

  @parameterized.parameters([
      prf.prf_key_templates.AES_CMAC, prf.prf_key_templates.HMAC_SHA256,
      prf.prf_key_templates.HMAC_SHA512, prf.prf_key_templates.HKDF_SHA256
  ])
  def test_compute_success(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(prf.PrfSet)
    output = primitive.primary().compute(b'input_data', output_length=15)
    self.assertLen(output, 15)
    self.assertEqual(
        primitive.primary().compute(b'input_data', output_length=15), output)
    self.assertNotEqual(
        primitive.primary().compute(b'some_other_data', output_length=15),
        output)
    prfs = primitive.all()
    self.assertLen(prfs, 1)
    self.assertEqual(
        prfs[primitive.primary_id()].compute(b'input_data', output_length=15),
        output)

  @parameterized.parameters([
      prf.prf_key_templates.AES_CMAC, prf.prf_key_templates.HMAC_SHA256,
      prf.prf_key_templates.HMAC_SHA512, prf.prf_key_templates.HKDF_SHA256
  ])
  def test_output_too_long_raises_error(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(prf.PrfSet)
    with self.assertRaises(tink.TinkError):
      primitive.primary().compute(b'input_data', output_length=1234567)
    prfs = primitive.all()
    self.assertLen(prfs, 1)
    p = prfs[primitive.primary_id()]
    with self.assertRaises(tink.TinkError):
      p.compute(b'input_data', output_length=1234567)

if __name__ == '__main__':
  absltest.main()
