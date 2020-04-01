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

"""Tink package."""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink import aead
from tink import core
from tink import daead
from tink import hybrid
from tink import mac
from tink import signature
from tink import streaming_aead
from tink import tink_config


Aead = aead.Aead
DeterministicAead = daead.DeterministicAead
HybridDecrypt = hybrid.HybridDecrypt
HybridEncrypt = hybrid.HybridEncrypt
Mac = mac.Mac
PublicKeySign = signature.PublicKeySign
PublicKeyVerify = signature.PublicKeyVerify
StreamingAead = streaming_aead.StreamingAead

KeyManager = core.KeyManager
PrivateKeyManager = core.PrivateKeyManager

Registry = core.Registry

new_keyset_handle = core.new_keyset_handle
read_keyset_handle = core.read_keyset_handle
KeysetHandle = core.KeysetHandle


KeysetReader = core.KeysetReader
JsonKeysetReader = core.JsonKeysetReader
BinaryKeysetReader = core.BinaryKeysetReader

KeysetWriter = core.KeysetWriter
JsonKeysetWriter = core.JsonKeysetWriter
BinaryKeysetWriter = core.BinaryKeysetWriter

new_primitive_set = core.new_primitive_set

TinkError = core.TinkError
