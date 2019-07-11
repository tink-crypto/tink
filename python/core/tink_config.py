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

"""Static methods for handling of Tink configurations."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from tink.python import aead
from tink.python import daead
from tink.python import hybrid
from tink.python import mac
from tink.python import signature
from tink.python.aead import aead_key_manager
from tink.python.cc.clif import cc_tink_config
from tink.python.core import registry
from tink.python.daead import deterministic_aead_key_manager
from tink.python.hybrid import hybrid_decrypt_key_manager
from tink.python.hybrid import hybrid_encrypt_key_manager
from tink.python.mac import mac_key_manager
from tink.python.signature import public_key_sign_key_manager
from tink.python.signature import public_key_verify_key_manager


KEY_MANAGER_GENERATORS = {
    'Aead': aead_key_manager.from_cc_registry,
    'DeterministicAead': deterministic_aead_key_manager.from_cc_registry,
    'HybridDecrypt': hybrid_decrypt_key_manager.from_cc_registry,
    'HybridEncrypt': hybrid_encrypt_key_manager.from_cc_registry,
    'Mac': mac_key_manager.from_cc_registry,
    'PublicKeySign': public_key_sign_key_manager.from_cc_registry,
    'PublicKeyVerify': public_key_verify_key_manager.from_cc_registry,
}


def register():
  cc_tink_config.register()
  _register_key_managers()
  _register_primitive_wrappers()


def latest():
  return cc_tink_config.latest()


def _register_key_managers():
  for entry in cc_tink_config.latest().entry:
    if entry.primitive_name in KEY_MANAGER_GENERATORS:
      registry.Registry.register_key_manager(
          KEY_MANAGER_GENERATORS[entry.primitive_name](entry.type_url),
          entry.new_key_allowed)


def _register_primitive_wrappers():
  """Registers all primitive wrappers."""
  register_primitive_wrapper = registry.Registry.register_primitive_wrapper
  register_primitive_wrapper(aead.AeadWrapper())
  register_primitive_wrapper(daead.DeterministicAeadWrapper())
  register_primitive_wrapper(hybrid.HybridDecryptWrapper())
  register_primitive_wrapper(hybrid.HybridEncryptWrapper())
  register_primitive_wrapper(mac.MacWrapper())
  register_primitive_wrapper(signature.PublicKeySignWrapper())
  register_primitive_wrapper(signature.PublicKeyVerifyWrapper())
