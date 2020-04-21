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

from tink import aead
from tink import core
from tink import daead
from tink import hybrid
from tink import mac
from tink import signature
from tink.cc.pybind import cc_tink_config


def register():
  aead.register()
  daead.register()
  hybrid.register()
  mac.register()
  cc_tink_config.register()
  _register_key_managers()
  _register_primitive_wrappers()


def _register_key_managers():
  """Registers all currently known key managers in the Python registry."""
  for key_type_identifier in ('EcdsaPrivateKey', 'Ed25519PrivateKey',
                              'RsaSsaPssPrivateKey', 'RsaSsaPkcs1PrivateKey',):
    _register_cc_key_manager(
        signature.sign_key_manager_from_cc_registry, key_type_identifier)

  for key_type_identifier in ('EcdsaPublicKey', 'Ed25519PublicKey',
                              'RsaSsaPssPublicKey', 'RsaSsaPkcs1PublicKey',):
    _register_cc_key_manager(
        signature.verify_key_manager_from_cc_registry, key_type_identifier)


def _register_cc_key_manager(key_manager_from_cc_registry,
                             type_identifier,
                             new_key_allowed=True):
  """Obtains a cc key manager and adds it to the Python registry."""

  core.Registry.register_key_manager(
      key_manager_from_cc_registry(
          'type.googleapis.com/google.crypto.tink.{}'.format(type_identifier)),
      new_key_allowed)


def _register_primitive_wrappers():
  """Registers all primitive wrappers."""
  register_primitive_wrapper = core.Registry.register_primitive_wrapper
  register_primitive_wrapper(signature.PublicKeySignWrapper())
  register_primitive_wrapper(signature.PublicKeyVerifyWrapper())
