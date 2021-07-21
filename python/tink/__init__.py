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

from tink import _keyset_handle
from tink import _keyset_reader
from tink import _keyset_writer
from tink import core

new_keyset_handle = _keyset_handle.new_keyset_handle
read_keyset_handle = _keyset_handle.read_keyset_handle
read_keyset_handle_with_associated_data = _keyset_handle.read_keyset_handle_with_associated_data
read_no_secret_keyset_handle = _keyset_handle.read_no_secret_keyset_handle
KeysetHandle = _keyset_handle.KeysetHandle

KeysetReader = _keyset_reader.KeysetReader
JsonKeysetReader = _keyset_reader.JsonKeysetReader
BinaryKeysetReader = _keyset_reader.BinaryKeysetReader

KeysetWriter = _keyset_writer.KeysetWriter
JsonKeysetWriter = _keyset_writer.JsonKeysetWriter
BinaryKeysetWriter = _keyset_writer.BinaryKeysetWriter

TinkError = core.TinkError
