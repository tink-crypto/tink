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

"""Python wrapper of the CLIF-wrapped C++ Public Key Verify key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text

from tink.cc.python import public_key_verify as cc_public_key_verify
from tink.python.cc.clif import cc_key_manager
from tink.python.core import key_manager
from tink.python.core import tink_error
from tink.python.signature import public_key_verify


class _PublicKeyVerifyCcToPyWrapper(public_key_verify.PublicKeyVerify):
  """Transforms cliffed C++ PublicKeyVerify into a Python primitive."""

  def __init__(self, cc_primitive: cc_public_key_verify.PublicKeyVerify):
    self._public_key_verify = cc_primitive

  @tink_error.use_tink_errors
  def verify(self, signature: bytes, data: bytes) -> None:
    self._public_key_verify.verify(signature, data)


def from_cc_registry(
    type_url: Text
) -> key_manager.KeyManager[public_key_verify.PublicKeyVerify]:
  return key_manager.KeyManagerCcToPyWrapper(
      cc_key_manager.PublicKeyVerifyKeyManager.from_cc_registry(type_url),
      public_key_verify.PublicKeyVerify, _PublicKeyVerifyCcToPyWrapper)
