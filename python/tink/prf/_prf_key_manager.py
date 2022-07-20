# Copyright 2020 Google LLC
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

"""Python wrapper of the wrapped C++ PRF Set key manager."""

from tink import core
from tink.cc.pybind import tink_bindings
from tink.prf import _prf_set
from tink.prf import _prf_set_wrapper


class PrfCcToPyWrapper(_prf_set.Prf):
  """Transforms C++ Prf primitive into a Python Prf primitive."""

  def __init__(self, cc_primitive: tink_bindings.Prf):
    self._cc_primitive = cc_primitive

  @core.use_tink_errors
  def compute(self, input_data: bytes, output_length: int) -> bytes:
    return self._cc_primitive.compute(input_data, output_length)


def register() -> None:
  """Registers all PrfSet key managers and PrfSet wrapper in the Registry."""
  tink_bindings.register()
  for ident in (
      'AesCmacPrfKey',
      'HmacPrfKey',
      'HkdfPrfKey',
  ):
    type_url = 'type.googleapis.com/google.crypto.tink.{}'.format(ident)
    key_manager = core.KeyManagerCcToPyWrapper(
        tink_bindings.PrfKeyManager.from_cc_registry(type_url),
        _prf_set.Prf, PrfCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)
  core.Registry.register_primitive_wrapper(_prf_set_wrapper.PrfSetWrapper())
