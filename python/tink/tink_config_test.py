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

"""Tests for tink.python.tink.tink_config."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import aead
from tink import core
from tink import daead
from tink import hybrid
from tink import mac
from tink import signature
from tink import tink_config


def setUpModule():
  tink_config.register()


def _primitive_and_key(key_data, primitive_class, output_prefix_type):
  primitive = core.Registry.primitive(key_data, primitive_class)
  key = tink_pb2.Keyset.Key(
      key_id=1, status=tink_pb2.ENABLED, output_prefix_type=output_prefix_type)
  key.key_data.CopyFrom(key_data)
  return primitive, key


def _new_primitive_and_key(template, primitive_class, output_prefix_type):
  return _primitive_and_key(
      core.Registry.new_key_data(template), primitive_class, output_prefix_type)


def _public_primitive_and_key(private_key, primitive_class, output_prefix_type):
  return _primitive_and_key(
      core.Registry.public_key_data(private_key.key_data), primitive_class,
      output_prefix_type)


class TinkConfigTest(absltest.TestCase):

  def test_all_aead_templates_are_registered(self):
    for template in [
        aead.aead_key_templates.AES128_EAX,
        aead.aead_key_templates.AES256_EAX,
        aead.aead_key_templates.AES128_GCM,
        aead.aead_key_templates.AES256_GCM,
        aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
        aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
        aead.aead_key_templates.XCHACHA20_POLY1305
    ]:
      key_data = core.Registry.new_key_data(template)
      primitive = core.Registry.primitive(key_data, aead.Aead)
      self.assertEqual(
          primitive.decrypt(primitive.encrypt(b'message', b'ad'), b'ad'),
          b'message')

  def test_all_mac_templates_are_registered(self):
    for template in [
        mac.mac_key_templates.HMAC_SHA256_128BITTAG,
        mac.mac_key_templates.HMAC_SHA256_256BITTAG
    ]:
      key_data = core.Registry.new_key_data(template)
      primitive = core.Registry.primitive(key_data, mac.Mac)
      self.assertIsNone(
          primitive.verify_mac(primitive.compute_mac(b'data'), b'data'))

  def test_all_deterministic_aead_templates_are_registered(self):
    key_data = core.Registry.new_key_data(
        daead.deterministic_aead_key_templates.AES256_SIV)
    daead_primitive = core.Registry.primitive(key_data, daead.DeterministicAead)
    ciphertext = daead_primitive.encrypt_deterministically(b'message', b'ad')
    self.assertEqual(
        daead_primitive.decrypt_deterministically(ciphertext, b'ad'),
        b'message')

  def test_aead_wrapper_is_correctly_registered(self):
    aead1, key1 = _new_primitive_and_key(aead.aead_key_templates.AES128_EAX,
                                         aead.Aead, tink_pb2.RAW)
    aead2, key2 = _new_primitive_and_key(aead.aead_key_templates.AES256_GCM,
                                         aead.Aead, tink_pb2.TINK)
    pset = core.PrimitiveSet(aead.Aead)
    pset.add_primitive(aead1, key1)
    pset.set_primary(pset.add_primitive(aead2, key2))
    wrapped_aead = core.Registry.wrap(pset)

    self.assertEqual(
        wrapped_aead.decrypt(aead1.encrypt(b'plaintext1', b'ad1'), b'ad1'),
        b'plaintext1')
    self.assertEqual(
        wrapped_aead.decrypt(
            wrapped_aead.encrypt(b'plaintext2', b'ad2'), b'ad2'), b'plaintext2')

  def test_mac_wrapper_is_correctly_registered(self):
    mac1, key1 = _new_primitive_and_key(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG, mac.Mac, tink_pb2.RAW)
    mac2, key2 = _new_primitive_and_key(
        mac.mac_key_templates.HMAC_SHA256_256BITTAG, mac.Mac, tink_pb2.TINK)
    pset = core.PrimitiveSet(mac.Mac)
    pset.add_primitive(mac1, key1)
    pset.set_primary(pset.add_primitive(mac2, key2))
    wrapped_mac = core.Registry.wrap(pset)

    self.assertIsNone(
        wrapped_mac.verify_mac(mac1.compute_mac(b'data1'), b'data1'))
    self.assertIsNone(
        wrapped_mac.verify_mac(wrapped_mac.compute_mac(b'data2'), b'data2'))

  def test_deterministic_aead_wrapper_is_correctly_registered(self):
    daead1, key1 = _new_primitive_and_key(
        daead.deterministic_aead_key_templates.AES256_SIV,
        daead.DeterministicAead, tink_pb2.RAW)
    daead2, key2 = _new_primitive_and_key(
        daead.deterministic_aead_key_templates.AES256_SIV,
        daead.DeterministicAead, tink_pb2.TINK)
    pset = core.PrimitiveSet(daead.DeterministicAead)
    pset.add_primitive(daead1, key1)
    pset.set_primary(pset.add_primitive(daead2, key2))
    wrapped_daead = core.Registry.wrap(pset)

    self.assertEqual(
        wrapped_daead.decrypt_deterministically(
            daead1.encrypt_deterministically(b'plaintext1', b'ad1'), b'ad1'),
        b'plaintext1')
    self.assertEqual(
        wrapped_daead.decrypt_deterministically(
            wrapped_daead.encrypt_deterministically(b'plaintext2', b'ad2'),
            b'ad2'), b'plaintext2')

  def test_hybrid_wrappers_are_correctly_registered(self):
    dec1, dec1_key = _new_primitive_and_key(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
        hybrid.HybridDecrypt, tink_pb2.RAW)
    enc1, enc1_key = _public_primitive_and_key(dec1_key, hybrid.HybridEncrypt,
                                               tink_pb2.RAW)

    dec2, dec2_key = _new_primitive_and_key(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
        hybrid.HybridDecrypt, tink_pb2.RAW)
    enc2, enc2_key = _public_primitive_and_key(dec2_key, hybrid.HybridEncrypt,
                                               tink_pb2.RAW)

    dec_pset = core.PrimitiveSet(hybrid.HybridDecrypt)
    dec_pset.add_primitive(dec1, dec1_key)
    dec_pset.set_primary(dec_pset.add_primitive(dec2, dec2_key))
    wrapped_dec = core.Registry.wrap(dec_pset)

    enc_pset = core.PrimitiveSet(hybrid.HybridEncrypt)
    enc_pset.add_primitive(enc1, enc1_key)
    enc_pset.set_primary(enc_pset.add_primitive(enc2, enc2_key))
    wrapped_enc = core.Registry.wrap(enc_pset)

    self.assertEqual(
        wrapped_dec.decrypt(enc1.encrypt(b'plaintext1', b'ad1'), b'ad1'),
        b'plaintext1')
    self.assertEqual(
        wrapped_dec.decrypt(wrapped_enc.encrypt(b'plaintext2', b'ad2'), b'ad2'),
        b'plaintext2')

  def test_key_managers_for_signature_templates_are_registered(self):
    key_templates = signature.signature_key_templates
    for template in [
        key_templates.ECDSA_P256, key_templates.ECDSA_P384,
        key_templates.ECDSA_P521, key_templates.ECDSA_P256_IEEE_P1363,
        key_templates.ECDSA_P256_IEEE_P1363,
        key_templates.ECDSA_P521_IEEE_P1363, key_templates.ED25519,
        key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
        key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
        key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
        key_templates.RSA_SSA_PKCS1_4096_SHA512_F4
    ]:
      key_data = core.Registry.new_key_data(template)
      primitive = core.Registry.primitive(key_data, signature.PublicKeySign)
      sig = primitive.sign(b'data')

      public_key = core.Registry.public_key_data(key_data)
      primitive_verify = core.Registry.primitive(public_key,
                                                 signature.PublicKeyVerify)

      primitive_verify.verify(sig, b'data')

  def test_signature_wrapper_is_correctly_registered(self):
    sig1, key1 = _new_primitive_and_key(
        signature.signature_key_templates.ECDSA_P256, signature.PublicKeySign,
        tink_pb2.TINK)
    sig2, key2 = _new_primitive_and_key(
        signature.signature_key_templates.ECDSA_P256, signature.PublicKeySign,
        tink_pb2.TINK)

    ver1, pubkey1 = _public_primitive_and_key(key1, signature.PublicKeyVerify,
                                              tink_pb2.TINK)
    ver2, pubkey2 = _public_primitive_and_key(key2, signature.PublicKeyVerify,
                                              tink_pb2.TINK)

    pset = core.PrimitiveSet(signature.PublicKeySign)
    pset.add_primitive(sig1, key1)
    pset.set_primary(pset.add_primitive(sig2, key2))
    wrapped_sig = core.Registry.wrap(pset)

    pset_verify = core.new_primitive_set(signature.PublicKeyVerify)
    pset_verify.add_primitive(ver1, pubkey1)
    pset_verify.set_primary(pset_verify.add_primitive(ver2, pubkey2))
    wrapped_ver = core.Registry.wrap(pset_verify)

    sig = wrapped_sig.sign(b'data')
    wrapped_ver.verify(sig, b'data')


if __name__ == '__main__':
  absltest.main()
