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

"""Python wrapper of the wrapped C++ AEAD key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink import core
from tink.aead import _aead
from tink.aead import _aead_wrapper
from tink.cc.pybind import tink_bindings


class AeadCcToPyWrapper(_aead.Aead):
  """Transforms C++ Aead primitive into a Python primitive."""

  def __init__(self, cc_primitive: tink_bindings.Aead):
    self._aead = cc_primitive

  @core.use_tink_errors
  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    return self._aead.encrypt(plaintext, associated_data)

  @core.use_tink_errors
  def decrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    return self._aead.decrypt(plaintext, associated_data)


def register() -> None:
  """Registers all AEAD key managers and AEAD wrapper in the Registry."""
  tink_bindings.register()
  for ident in (
      'AesCtrHmacAeadKey',
      'AesGcmKey',
      'AesGcmSivKey',
      'AesEaxKey',
      'XChaCha20Poly1305Key',
      'KmsAeadKey',
      'KmsEnvelopeAeadKey',
  ):
    type_url = 'type.googleapis.com/google.crypto.tink.{}'.format(ident)
    key_manager = core.KeyManagerCcToPyWrapper(
        tink_bindings.AeadKeyManager.from_cc_registry(type_url), _aead.Aead,
        AeadCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)
  core.Registry.register_primitive_wrapper(_aead_wrapper.AeadWrapper())
