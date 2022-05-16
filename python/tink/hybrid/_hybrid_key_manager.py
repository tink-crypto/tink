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

"""Python wrapper of the wrapped C++ Hybrid En- and Decryption key manager."""

from tink import core
from tink.cc.pybind import tink_bindings
from tink.hybrid import _hybrid_decrypt
from tink.hybrid import _hybrid_encrypt
from tink.hybrid import _hybrid_wrapper


class _HybridDecryptCcToPyWrapper(_hybrid_decrypt.HybridDecrypt):
  """Transforms C++ HybridDecrypt primitive into a Python primitive."""

  def __init__(self, cc_primitive: tink_bindings.HybridDecrypt):
    self._hybrid_decrypt = cc_primitive

  @core.use_tink_errors
  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    return self._hybrid_decrypt.decrypt(ciphertext, context_info)


class _HybridEncryptCcToPyWrapper(_hybrid_encrypt.HybridEncrypt):
  """Transforms C++ HybridEncrypt primitive into a Python primitive."""

  def __init__(self, cc_primitive: tink_bindings.HybridEncrypt):
    self._hybrid_encrypt = cc_primitive

  @core.use_tink_errors
  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    return self._hybrid_encrypt.encrypt(plaintext, context_info)


def register():
  """Registers all Hybrid key managers and wrapper in the Python Registry."""
  tink_bindings.register()
  tink_bindings.register_hpke()

  # Register primitive wrappers.
  core.Registry.register_primitive_wrapper(
      _hybrid_wrapper.HybridDecryptWrapper())
  core.Registry.register_primitive_wrapper(
      _hybrid_wrapper.HybridEncryptWrapper())

  # Register ECIES-AEAD-HKDF key managers.
  decrypt_type_url = (
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey')
  decrypt_key_manager = core.PrivateKeyManagerCcToPyWrapper(
      tink_bindings.HybridDecryptKeyManager.from_cc_registry(decrypt_type_url),
      _hybrid_decrypt.HybridDecrypt, _HybridDecryptCcToPyWrapper)
  core.Registry.register_key_manager(decrypt_key_manager, new_key_allowed=True)

  encrypt_type_url = (
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey')
  encrypt_key_manager = core.KeyManagerCcToPyWrapper(
      tink_bindings.HybridEncryptKeyManager.from_cc_registry(encrypt_type_url),
      _hybrid_encrypt.HybridEncrypt, _HybridEncryptCcToPyWrapper)
  core.Registry.register_key_manager(encrypt_key_manager, new_key_allowed=True)

  # Register HPKE key managers.
  hpke_decrypt_type_url = (
      'type.googleapis.com/google.crypto.tink.HpkePrivateKey')
  hpke_decrypt_key_manager = core.PrivateKeyManagerCcToPyWrapper(
      tink_bindings.HybridDecryptKeyManager.from_cc_registry(
          hpke_decrypt_type_url), _hybrid_decrypt.HybridDecrypt,
      _HybridDecryptCcToPyWrapper)
  core.Registry.register_key_manager(
      hpke_decrypt_key_manager, new_key_allowed=True)

  hpke_encrypt_type_url = (
      'type.googleapis.com/google.crypto.tink.HpkePublicKey')
  hpke_encrypt_key_manager = core.KeyManagerCcToPyWrapper(
      tink_bindings.HybridEncryptKeyManager.from_cc_registry(
          hpke_encrypt_type_url), _hybrid_encrypt.HybridEncrypt,
      _HybridEncryptCcToPyWrapper)
  core.Registry.register_key_manager(
      hpke_encrypt_key_manager, new_key_allowed=True)
