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

"""Python wrapper of the CLIF-wrapped C++ AEAD key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text

from tink.cc.python import aead as cc_aead
from tink.python.aead import aead
from tink.python.cc.clif import cc_key_manager
from tink.python.core import key_manager
from tink.python.core import tink_error


class _AeadCcToPyWrapper(aead.Aead):
  """Transforms cliffed C++ Aead primitive into a Python primitive."""

  def __init__(self, cc_primitive: cc_aead.Aead):
    self._aead = cc_primitive

  @tink_error.use_tink_errors
  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    return self._aead.encrypt(plaintext, associated_data)

  @tink_error.use_tink_errors
  def decrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    return self._aead.decrypt(plaintext, associated_data)


def from_cc_registry(type_url: Text) -> key_manager.KeyManager[aead.Aead]:
  return key_manager.KeyManagerCcToPyWrapper(
      cc_key_manager.AeadKeyManager.from_cc_registry(type_url), aead.Aead,
      _AeadCcToPyWrapper)
