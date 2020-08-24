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

# Placeholder for import for type annotations

from typing import cast, Mapping, Type, TypeVar, Text
from absl.testing import absltest

from tink.proto import tink_pb2

from tink import aead
from tink import core
from tink import hybrid
from tink import mac
from tink import prf
from tink.mac import _mac_wrapper
from tink.prf import _prf_set_wrapper
from tink.testing import helper


P = TypeVar('P')


class DummyKeyManager(core.KeyManager[P]):

  def __init__(self, type_url: Text, primitive_class: Type[P] = aead.Aead):
    self._type_url = type_url
    self._primitive_class = primitive_class

  def primitive_class(self) -> Type[P]:
    return self._primitive_class

  def primitive(self, key_data: tink_pb2.KeyData) -> P:
    return helper.FakeAead()

  def key_type(self) -> Text:
    return self._type_url

  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    return tink_pb2.KeyData(type_url=key_template.type_url)

  def does_support(self, type_url: Text) -> bool:
    return self.key_type() == type_url


class UnsupportedKeyManager(DummyKeyManager[P]):

  def does_support(self, type_url: Text) -> bool:
    return False


class DummyPrivateKeyManager(core.PrivateKeyManager[hybrid.HybridDecrypt]):

  def __init__(self, type_url: Text):
    self._type_url = type_url

  def primitive_class(self) -> Type[hybrid.HybridDecrypt]:
    return hybrid.HybridDecrypt

  def primitive(self, key_data: tink_pb2.KeyData) -> hybrid.HybridDecrypt:
    return helper.FakeHybridDecrypt()

  def key_type(self) -> Text:
    return self._type_url

  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    return tink_pb2.KeyData()

  def public_key_data(
      self, private_key_data: tink_pb2.KeyData) -> tink_pb2.KeyData:
    return tink_pb2.KeyData(type_url='public_' + private_key_data.type_url)


class DummyMacWrapper(core.PrimitiveWrapper[mac.Mac, mac.Mac]):

  def wrap(self, pset: core.PrimitiveSet) -> mac.Mac:
    _ = pset
    return helper.FakeMac()

  def primitive_class(self) -> Type[mac.Mac]:
    return mac.Mac

  def input_primitive_class(self) -> Type[mac.Mac]:
    return mac.Mac


class InconsistentWrapper(core.PrimitiveWrapper[mac.Mac, mac.Mac]):

  def wrap(self, pset: core.PrimitiveSet) -> mac.Mac:
    _ = pset
    # returns a primitive of the wrong type
    return cast(mac.Mac, helper.FakeAead())

  def primitive_class(self) -> Type[mac.Mac]:
    return mac.Mac

  def input_primitive_class(self) -> Type[mac.Mac]:
    return mac.Mac


class _WrappedPrfSet(prf.PrfSet):
  """Implements PrfSet for a set of Prf primitives."""

  def __init__(self, primitive_set: core.PrimitiveSet):
    self._primitive_set = primitive_set

  def primary_id(self) -> int:
    return self._primitive_set.primary().key_id

  def all(self) -> Mapping[int, prf.Prf]:
    return {
        entry.key_id: entry.primitive
        for entry in self._primitive_set.raw_primitives()
    }

  def primary(self) -> prf.Prf:
    return self._primitive_set.primary().primitive


class PrfToPrfSetWrapper(core.PrimitiveWrapper[prf.Prf, prf.PrfSet]):
  """A PrimitiveWrapper that wraps Prfs into a PrfSet."""

  def wrap(self, primitives_set: core.PrimitiveSet) -> _WrappedPrfSet:
    return _WrappedPrfSet(primitives_set)

  def primitive_class(self) -> Type[prf.PrfSet]:
    return prf.PrfSet

  def input_primitive_class(self) -> Type[prf.Prf]:
    return prf.Prf


class _InvalidPrf(prf.Prf):

  def compute(self, input_data: bytes, output_length: int) -> bytes:
    raise core.TinkError('Invalid Prf')


class PrfToPrfWrapper(core.PrimitiveWrapper[prf.Prf, prf.Prf]):
  """A PrimitiveWrapper that wraps Prfs into a Prf."""

  def wrap(self, primitives_set: core.PrimitiveSet) -> prf.Prf:
    if primitives_set.primary():
      return primitives_set.primary().primitive
    else:
      return _InvalidPrf()

  def primitive_class(self) -> Type[prf.Prf]:
    return prf.Prf

  def input_primitive_class(self) -> Type[prf.Prf]:
    return prf.Prf


def _mac_set(mac_list) -> core.PrimitiveSet[mac.Mac]:
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
    with self.assertRaises(core.TinkError):
      self.reg.primitive(tink_pb2.KeyData(type_url='dummy_type_url'), mac.Mac)

  def test_primitive_fails_on_subclass(self):
    self.reg.register_key_manager(
        DummyKeyManager('dummy_type_url', helper.FakeAead))
    with self.assertRaises(core.TinkError):
      self.reg.primitive(tink_pb2.KeyData(type_url='dummy_type_url'), aead.Aead)

  def test_new_key_data_success(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    key_template = tink_pb2.KeyTemplate(type_url='dummy_type_url')
    key_data = self.reg.new_key_data(key_template)
    self.assertEqual(key_data.type_url, 'dummy_type_url')

  def test_new_key_data_wrong_type_url(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    unknown_key_template = tink_pb2.KeyTemplate(type_url='unknown_type_url')
    with self.assertRaises(core.TinkError):
      self.reg.new_key_data(unknown_key_template)

  def test_new_key_data_no_new_key_allowed(self):
    self.reg.register_key_manager(
        DummyKeyManager('dummy_type_url'), new_key_allowed=False)
    key_template = tink_pb2.KeyTemplate(type_url='dummy_type_url')
    with self.assertRaises(core.TinkError):
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
    with self.assertRaises(core.TinkError):
      self.reg.public_key_data(key_data)

  def test_public_key_data_fails_for_non_private_key_manager(self):
    self.reg.register_key_manager(DummyKeyManager('dummy_type_url'))
    key_data = tink_pb2.KeyData(
        type_url='dummy_type_url',
        key_material_type=tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    with self.assertRaises(core.TinkError):
      self.reg.public_key_data(key_data)

  def test_wrap_success(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    mac1 = helper.FakeMac('FakeMac1')
    mac2 = helper.FakeMac('FakeMac2')
    wrapped_mac = self.reg.wrap(_mac_set([mac1, mac2]), mac.Mac)
    wrapped_mac.verify_mac(mac1.compute_mac(b'data1'), b'data1')
    wrapped_mac.verify_mac(mac2.compute_mac(b'data2'), b'data2')
    wrapped_mac.verify_mac(wrapped_mac.compute_mac(b'data'), b'data')

  def test_wrap_with_primitive_class_success(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    mac1 = helper.FakeMac('FakeMac1')
    mac2 = helper.FakeMac('FakeMac2')
    wrapped_mac = self.reg.wrap(_mac_set([mac1, mac2]), mac.Mac)
    wrapped_mac.verify_mac(mac1.compute_mac(b'data1'), b'data1')
    wrapped_mac.verify_mac(mac2.compute_mac(b'data2'), b'data2')
    wrapped_mac.verify_mac(wrapped_mac.compute_mac(b'data'), b'data')

  def test_wrap_with_incompatible_primitive_class_fails(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    pset = core.new_primitive_set(prf.Prf)
    prf1 = helper.FakePrf('FakePrf1')
    pset.set_primary(
        pset.add_primitive(
            prf1,
            helper.fake_key(key_id=1234, output_prefix_type=tink_pb2.RAW)))
    with self.assertRaises(core.TinkError):
      _ = self.reg.wrap(pset, mac.Mac)

  def test_wrap_unknown_primitive(self):
    with self.assertRaises(core.TinkError):
      self.reg.wrap(_mac_set([helper.FakeMac()]), mac.Mac)

  def test_primitive_wrapper_reset(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    self.reg.reset()
    with self.assertRaises(core.TinkError):
      self.reg.wrap(_mac_set([helper.FakeMac()]), mac.Mac)

  def test_register_same_primitive_wrapper_twice(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())

  def test_register_different_primitive_wrappers_twice_fails(self):
    self.reg.register_primitive_wrapper(_mac_wrapper.MacWrapper())
    with self.assertRaises(core.TinkError):
      self.reg.register_primitive_wrapper(DummyMacWrapper())

  def test_register_inconsistent_wrapper_fails(self):
    with self.assertRaises(core.TinkError):
      self.reg.register_primitive_wrapper(InconsistentWrapper())

  def test_register_prf_to_prfset_wrapper_success(self):
    self.reg.register_primitive_wrapper(PrfToPrfSetWrapper())
    pset = core.new_primitive_set(prf.Prf)
    prf1 = helper.FakePrf('FakePrf1')
    prf2 = helper.FakePrf('FakePrf2')
    pset.add_primitive(
        prf1,
        helper.fake_key(key_id=1234, output_prefix_type=tink_pb2.RAW))
    pset.set_primary(
        pset.add_primitive(
            prf2,
            helper.fake_key(key_id=5678, output_prefix_type=tink_pb2.RAW)))
    wrapped_prf_set = self.reg.wrap(pset, prf.PrfSet)

    expected_output1 = prf1.compute(b'input', output_length=31)
    expected_output2 = prf2.compute(b'input', output_length=31)

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

  def test_two_wrappers_with_equal_primitive_class_fails(self):
    self.reg.register_primitive_wrapper(_prf_set_wrapper.PrfSetWrapper())
    # Only one wrapper for a output primitive is allowed.
    with self.assertRaises(core.TinkError):
      self.reg.register_primitive_wrapper(PrfToPrfSetWrapper())

  def test_two_wrappers_with_equal_input_primitive_class_success(self):
    self.reg.register_primitive_wrapper(PrfToPrfSetWrapper())
    # this is allowed, since PrfToPrfWrapper has a different output primitive.
    self.reg.register_primitive_wrapper(PrfToPrfWrapper())
    pset = core.new_primitive_set(prf.Prf)
    prf1 = helper.FakePrf('FakePrf1')
    prf2 = helper.FakePrf('FakePrf2')
    pset.add_primitive(
        prf1,
        helper.fake_key(key_id=1234, output_prefix_type=tink_pb2.RAW))
    pset.set_primary(
        pset.add_primitive(
            prf2,
            helper.fake_key(key_id=5678, output_prefix_type=tink_pb2.RAW)))

    wrapped_prf_set = self.reg.wrap(pset, prf.PrfSet)
    wrapped_prf = self.reg.wrap(pset, prf.Prf)

    expected_output2 = prf2.compute(b'input', output_length=31)

    self.assertEqual(
        wrapped_prf_set.primary().compute(b'input', output_length=31),
        expected_output2)
    self.assertEqual(
        wrapped_prf.compute(b'input', output_length=31),
        expected_output2)

if __name__ == '__main__':
  absltest.main()
