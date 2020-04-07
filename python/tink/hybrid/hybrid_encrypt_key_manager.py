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

"""Python wrapper of the CLIF-wrapped C++ Hybrid En- and Decryption key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text


from tink import core
from tink.cc.pybind import cc_key_manager
from tink.cc.pybind import hybrid_encrypt as cc_hybrid_encrypt
from tink.hybrid import hybrid_encrypt


class _HybridEncryptCcToPyWrapper(hybrid_encrypt.HybridEncrypt):
  """Transforms cliffed C++ HybridEncrypt primitive into a Python primitive."""

  def __init__(self, cc_primitive: cc_hybrid_encrypt.HybridEncrypt):
    self._hybrid_encrypt = cc_primitive

  @core.use_tink_errors
  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    return self._hybrid_encrypt.encrypt(plaintext, context_info)


def from_cc_registry(
    type_url: Text) -> core.KeyManager[hybrid_encrypt.HybridEncrypt]:
  return core.KeyManagerCcToPyWrapper(
      cc_key_manager.HybridEncryptKeyManager.from_cc_registry(type_url),
      hybrid_encrypt.HybridEncrypt, _HybridEncryptCcToPyWrapper)
