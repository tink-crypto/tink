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

"""Tests for tink.python.tink.registry."""
from absl.testing import absltest

from tink.proto import tink_pb2

from tink import aead
from tink import core
from tink import mac
from tink.mac import _mac_wrapper
from tink.testing import helper


class DummyKeyManager(core.KeyManager):

  def __init__(self, type_url, primitive_class=aead.Aead):
    self._type_url = type_url
    self._primitive_class = primitive_class

  def primitive_class(self):
    return self._primitive_class

  def primitive(self, key_data):
    return helper.FakeAead()

  def key_type(self):
    return self._type_url

  def new_key_data(self, key_template):
    return tink_pb2.KeyData(type_url=key_template.type_url)


class UnsupportedKeyManager(DummyKeyManager):

  def does_support(self, type_url):
    return False


class DummyPrivateKeyManager(core.PrivateKeyManager):

  def __init__(self, type_url):
    self._type_url = type_url

  def primitive_class(self):
    return None

  def primitive(self, key_data):
    return None

  def key_type(self):
    return self._type_url

  def new_key_data(self, key_template):
    return None

  def public_key_data(self, private_key_data):
    return tink_pb2.KeyData(type_url='public_' + private_key_data.type_url)


class DummyMacWrapper(core.PrimitiveWrapper):

  def wrap(self, _):
    return helper.FakeMac()

  def primitive_class(self):
    return mac.Mac


class InconsistentWrapper(core.PrimitiveWrapper):

  def wrap(self, _):
    return helper.FakeAead()

  def primitive_class(self):
    return mac.Mac


def _mac_set(mac_list):
  """Converts a List of Mac in a PrimitiveSet and sets the last primary."""
  mac_set = core.new_primitive_set(mac.Mac)
  for i, primitive in enumerate(mac_list):
    mac_set.set_primary(
        mac_set.add_primitive(
            primitive,
            helper.fake_key(key_id=i, output_prefix_type=tink_pb2.RAW)))
  return mac_set


class RegistryTest(absltest.TestCase):

  def setUp(self):
    super(RegistryTest, self).setUp()
    self.reg = core.Registry()
    self.reg.reset()

  def test_key_manager_no_exist(self):
    with self.assertRaises(core.TinkError):
      self.reg.key_manager('invalid')

  def test_key_manager_register(self):
    dummy_key_manager = DummyKeyManager('dummy_type_url')
    self.reg.register_key_manager(dummy_key_manager)
    self.assertEqual(dummy_key_manager, self.reg.key_manager('dummy_type_url'))

  def test_key_manager_reset(self):
    dummy_key_manager = DummyKeyManager('dummy_type_url')
    self.reg.register_key_manager(dummy_key_manager)
    self.reg.reset()
    with self.assertRaises(core.TinkError):
      self.reg.key_manager('dummy_type_url')

  def test_register_same_key_manager_twice(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url', aead.Aead))
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url', aead.Aead))

  def test_register_unsupported_key_manager_fails(self):
    with self.assertRaises(core.TinkError):
      self.reg.register_key_manager(UnsupportedKeyManager('unsupported'))

  def test_key_manager_replace_fails(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url', aead.Aead))
    # Replacing the primitive_class for a type_url not allowed.
    with self.assertRaises(core.TinkError):
      self.reg.register_key_manager(
          DummyKeyManager('dummy_type_url', mac.Mac), new_key_allowed=False)

  def test_key_manager_disable_new_key_enable_fails(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    # Disable new keys.
    self.reg.register_key_manager(
        DummyKeyManager('dummy_type_url'), new_key_allowed=False)
    # Check new keys can't be enabled again.
    with self.assertRaises(core.TinkError):
      self.reg.register_key_manager(
          DummyKeyManager('dummy_type_url'), new_key_allowed=True)

  def test_primitive_ok(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url', aead.Aead))
    primitive = self.reg.primitive(
        tink_pb2.KeyData(type_url='dummy_type_url'), aead.Aead)
    self.assertIsInstance(primitive, helper.FakeAead)

  def test_primitive_fails_on_wrong_primitive(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url', aead.Aead))
    with self.assertRaisesRegex(core.TinkError,
                                'uses primitive Aead, and not Mac'):
      self.reg.primitive(tink_pb2.KeyData(type_url='dummy_type_url'), mac.Mac)

  def test_primitive_fails_on_subclass(self):
    self.reg.register_key_manager(
        DummyKeyManager('dummy_type_url', helper.FakeAead))
    with self.assertRaisesRegex(core.TinkError,
                                'uses primitive FakeAead, and not Aead'):
      self.reg.primitive(tink_pb2.KeyData(type_url='dummy_type_url'), aead.Aead)

  def test_new_key_data_success(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    key_template = tink_pb2.KeyTemplate(type_url='dummy_type_url')
    key_data = self.reg.new_key_data(key_template)
    self.assertEqual(key_data.type_url, 'dummy_type_url')

  def test_new_key_data_wrong_type_url(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    unknown_key_template = tink_pb2.KeyTemplate(type_url='unknown_type_url')
    with self.assertRaisesRegex(core.TinkError,
                                'No manager for type unknown_type_url'):
      self.reg.new_key_data(unknown_key_template)

  def test_new_key_data_no_new_key_allowed(self):
    self.reg.register_key_manager(
        DummyKeyManager('dummy_type_url'), new_key_allowed=False)
    key_template = tink_pb2.KeyTemplate(type_url='dummy_type_url')
    with self.assertRaisesRegex(core.TinkError,
                                'does not allow for creation of new keys'):
      self.reg.new_key_data(key_template)

  def test_public_key_data_success(self):
    self.reg.register_key_manager(DummyPrivateKeyManager('dummy_type_url'))
    key_data = tink_pb2.KeyData(
        type_url='dummy_type_url',
        key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    public_key_data = self.reg.public_key_data(key_data)
    self.assertEqual(public_key_data.type_url, 'public_dummy_type_url')

  def test_public_key_data_fails_for_non_asymmetric_private_key(self):
    self.reg.register_key_manager(DummyPrivateKeyManager('dummy_type_url'))
    key_data = tink_pb2.KeyData(
        type_url='dummy_type_url',
        key_material_type=tink_pb2.KeyData.ASYMMETRIC_PUBLIC)
    with self.assertRaisesRegex(core.TinkError,
                                'contains a non-private key'):
      self.reg.public_key_data(key_data)

  def test_public_key_data_fails_for_non_private_key_manager(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    key_data = tink_pb2.KeyData(
        type_url='dummy_type_url',
        key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    with self.assertRaisesRegex(core.TinkError,
                                'is not a PrivateKeyManager'):
      self.reg.public_key_data(key_data)

  def test_wrap_success(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    mac1 = helper.FakeMac('FakeMac1')
    mac2 = helper.FakeMac('FakeMac2')
    wrapped_mac = self.reg.wrap(_mac_set([mac1, mac2]))
    wrapped_mac.verify_mac(mac1.compute_mac(b'data1'), b'data1')
    wrapped_mac.verify_mac(mac2.compute_mac(b'data2'), b'data2')
    wrapped_mac.verify_mac(wrapped_mac.compute_mac(b'data'), b'data')

  def test_wrap_unknown_primitive(self):
    with self.assertRaisesRegex(
        core.TinkError,
        'No PrimitiveWrapper registered for primitive Mac.'):
      self.reg.wrap(_mac_set([helper.FakeMac()]))

  def test_primitive_wrapper_reset(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    self.reg.reset()
    with self.assertRaisesRegex(
        core.TinkError,
        'No PrimitiveWrapper registered for primitive Mac.'):
      self.reg.wrap(_mac_set([helper.FakeMac()]))

  def test_register_same_primitive_wrapper_twice(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())

  def test_register_different_primitive_wrappers_twice_fails(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    with self.assertRaisesRegex(
        core.TinkError,
        'A wrapper for primitive Mac has already been added.'):
      self.reg.register_primitive_wrapper(DummyMacWrapper())

  def test_register_inconsistent_wrapper_fails(self):
    with self.assertRaisesRegex(
        core.TinkError,
        'Wrapper for primitive Mac generates incompatible primitive'):
      self.reg.register_primitive_wrapper(InconsistentWrapper())


if __name__ == '__main__':
  absltest.main()
