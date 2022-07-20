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

"""Python wrapper of the wrapped C++ Public Key Signature key manager."""

from tink import core
from tink.cc.pybind import tink_bindings
from tink.signature import _public_key_sign
from tink.signature import _public_key_verify
from tink.signature import _signature_wrapper


class _PublicKeySignCcToPyWrapper(_public_key_sign.PublicKeySign):
  """Transforms C++ PublicKeySign into a Python primitive."""

  def __init__(self, cc_primitive: tink_bindings.PublicKeySign):
    self._public_key_sign = cc_primitive

  @core.use_tink_errors
  def sign(self, data: bytes) -> bytes:
    return self._public_key_sign.sign(data)


class _PublicKeyVerifyCcToPyWrapper(_public_key_verify.PublicKeyVerify):
  """Transforms C++ PublicKeyVerify into a Python primitive."""

  def __init__(self, cc_primitive: tink_bindings.PublicKeyVerify):
    self._public_key_verify = cc_primitive

  @core.use_tink_errors
  def verify(self, signature: bytes, data: bytes) -> None:
    self._public_key_verify.verify(signature, data)


def register():
  """Registers all signature key managers in the Python registry."""
  tink_bindings.register()

  for key_type_identifier in ('EcdsaPrivateKey', 'Ed25519PrivateKey',
                              'RsaSsaPssPrivateKey', 'RsaSsaPkcs1PrivateKey',):
    type_url = 'type.googleapis.com/google.crypto.tink.' + key_type_identifier
    key_manager = core.PrivateKeyManagerCcToPyWrapper(
        tink_bindings.PublicKeySignKeyManager.from_cc_registry(type_url),
        _public_key_sign.PublicKeySign, _PublicKeySignCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)

  for key_type_identifier in ('EcdsaPublicKey', 'Ed25519PublicKey',
                              'RsaSsaPssPublicKey', 'RsaSsaPkcs1PublicKey',):
    type_url = 'type.googleapis.com/google.crypto.tink.' + key_type_identifier
    key_manager = core.KeyManagerCcToPyWrapper(
        tink_bindings.PublicKeyVerifyKeyManager.from_cc_registry(type_url),
        _public_key_verify.PublicKeyVerify, _PublicKeyVerifyCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)

  core.Registry.register_primitive_wrapper(
      _signature_wrapper.PublicKeySignWrapper())
  core.Registry.register_primitive_wrapper(
      _signature_wrapper.PublicKeyVerifyWrapper())
