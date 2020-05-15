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
"""Python wrapper of the wrapped C++ MAC key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink import core
from tink.cc.pybind import tink_bindings
from tink.mac import _mac
from tink.mac import _mac_wrapper


class _MacCcToPyWrapper(_mac.Mac):
  """Transforms C++ Mac primitive into a Python primitive."""

  def __init__(self, cc_primitive: tink_bindings.Mac):
    self._cc_mac = cc_primitive

  @core.use_tink_errors
  def compute_mac(self, data: bytes) -> bytes:
    return self._cc_mac.compute_mac(data)

  @core.use_tink_errors
  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    self._cc_mac.verify_mac(mac_value, data)


def register():
  tink_bindings.register()

  for key_type_identifier in ('HmacKey', 'AesCmacKey',):
    type_url = 'type.googleapis.com/google.crypto.tink.' + key_type_identifier
    key_manager = core.KeyManagerCcToPyWrapper(
        tink_bindings.MacKeyManager.from_cc_registry(type_url), _mac.Mac,
        _MacCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)
  core.Registry.register_primitive_wrapper(_mac_wrapper.MacWrapper())
