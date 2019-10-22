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
from __future__ import print_function

from tink.python.core import crypto_format as _crypto_format
from tink.python.core import key_manager
from tink.python.core import keyset_handle
from tink.python.core import keyset_reader
from tink.python.core import keyset_writer
from tink.python.core import primitive_set
from tink.python.core import primitive_wrapper
from tink.python.core import registry
from tink.python.core import tink_error


KeyManager = key_manager.KeyManager
PrivateKeyManager = key_manager.PrivateKeyManager

KeysetHandle = keyset_handle.KeysetHandle
new_keyset_handle = KeysetHandle.generate_new
read_keyset_handle = KeysetHandle.read
read_no_secret_keyset_handle = KeysetHandle.read_no_secret

KeysetReader = keyset_reader.KeysetReader
JsonKeysetReader = keyset_reader.JsonKeysetReader
BinaryKeysetReader = keyset_reader.BinaryKeysetReader

KeysetWriter = keyset_writer.KeysetWriter
JsonKeysetWriter = keyset_writer.JsonKeysetWriter
BinaryKeysetWriter = keyset_writer.BinaryKeysetWriter

Registry = registry.Registry

TinkError = tink_error.TinkError

new_primitive_set = primitive_set.new_primitive_set
PrimitiveSet = primitive_set.PrimitiveSet
PrimitiveWrapper = primitive_wrapper.PrimitiveWrapper

crypto_format = _crypto_format
