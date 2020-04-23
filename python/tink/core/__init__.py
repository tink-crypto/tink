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

"""Core package."""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.proto import tink_pb2
from tink.core import _crypto_format
from tink.core import _key_manager
from tink.core import _primitive_set
from tink.core import _primitive_wrapper
from tink.core import _registry
from tink.core import _tink_error


KeyManager = _key_manager.KeyManager
PrivateKeyManager = _key_manager.PrivateKeyManager

KeyManagerCcToPyWrapper = _key_manager.KeyManagerCcToPyWrapper
PrivateKeyManagerCcToPyWrapper = _key_manager.PrivateKeyManagerCcToPyWrapper

Registry = _registry.Registry

TinkError = _tink_error.TinkError
use_tink_errors = _tink_error.use_tink_errors

new_primitive_set = _primitive_set.new_primitive_set
PrimitiveSet = _primitive_set.PrimitiveSet
PrimitiveWrapper = _primitive_wrapper.PrimitiveWrapper

crypto_format = _crypto_format
