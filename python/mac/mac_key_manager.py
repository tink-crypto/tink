# Copyright 2020 Google LLC.
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
"""Python wrapper of the CLIF-wrapped C++ MAC key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text

from tink.cc.python import mac as cc_mac
from tink.python.cc.clif import cc_key_manager
from tink.python.core import key_manager
from tink.python.core import tink_error
from tink.python.mac import mac


class _MacCcToPyWrapper(mac.Mac):
  """Transforms cliffed C++ Mac primitive into a Python primitive."""

  def __init__(self, cc_primitive: cc_mac.Mac):
    self._cc_mac = cc_primitive

  @tink_error.use_tink_errors
  def compute_mac(self, data: bytes) -> bytes:
    return self._cc_mac.compute_mac(data)

  @tink_error.use_tink_errors
  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    self._cc_mac.verify_mac(mac_value, data)


def from_cc_registry(type_url: Text) -> key_manager.KeyManager[mac.Mac]:
  return key_manager.KeyManagerCcToPyWrapper(
      cc_key_manager.MacKeyManager.from_cc_registry(type_url), mac.Mac,
      _MacCcToPyWrapper)
