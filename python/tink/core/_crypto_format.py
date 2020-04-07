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

"""Constants and convenience methods for the outputs handled by Tink."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import struct

from tink.proto import tink_pb2
from tink.core import _tink_error

TINK_START_BYTE = b'\x01'
LEGACY_START_BYTE = b'\x00'
RAW_PREFIX_SIZE = 0
NON_RAW_PREFIX_SIZE = 5
TINK_PREFIX_SIZE = NON_RAW_PREFIX_SIZE
RAW_PREFIX = b''


def output_prefix(key: tink_pb2.Keyset.Key) -> bytes:
  """Generates the prefix for the outputs handled by the specified key."""
  if key.output_prefix_type == tink_pb2.TINK:
    return struct.pack('>cL', TINK_START_BYTE, key.key_id)
  elif (key.output_prefix_type == tink_pb2.CRUNCHY or
        key.output_prefix_type == tink_pb2.LEGACY):
    return struct.pack('>cL', LEGACY_START_BYTE, key.key_id)
  elif key.output_prefix_type == tink_pb2.RAW:
    return b''
  else:
    raise _tink_error.TinkError(
        'The given key has invalid OutputPrefixType {}.'.format(
            key.output_prefix_type))
