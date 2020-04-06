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
from tink.aead import aead
from tink.core import crypto_format as _crypto_format
from tink.core import key_manager
from tink.core import keyset_reader
from tink.core import keyset_writer
from tink.core import primitive_set
from tink.core import primitive_wrapper
from tink.core import registry
from tink.core import tink_error


KeyManager = key_manager.KeyManager
PrivateKeyManager = key_manager.PrivateKeyManager

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
