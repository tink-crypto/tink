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
"""Streaming AEAD wrapper."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
from typing import cast, BinaryIO, Type

from tink import core
from tink.streaming_aead import _raw_streaming_aead
from tink.streaming_aead import _streaming_aead


class _WrappedStreamingAead(_streaming_aead.StreamingAead):
  """_WrappedStreamingAead."""

  def __init__(self, primitives_set: core.PrimitiveSet):
    self._primitive_set = primitives_set

  def new_encrypting_stream(self, ciphertext_destination: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    raw = self._primitive_set.primary().primitive.new_raw_encrypting_stream(
        ciphertext_destination, associated_data)
    return cast(BinaryIO, io.BufferedWriter(raw))

  def new_decrypting_stream(self, ciphertext_source: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    # TODO(juerg): Implement a proper wrapper.
    # This implementation only works for keysets with a single key!
    raw = self._primitive_set.primary().primitive.new_raw_decrypting_stream(
        ciphertext_source, associated_data)
    return cast(BinaryIO, io.BufferedReader(raw))


class StreamingAeadWrapper(
    core.PrimitiveWrapper[_raw_streaming_aead.RawStreamingAead,
                          _streaming_aead.StreamingAead]):
  """StreamingAeadWrapper is the PrimitiveWrapper for StreamingAead."""

  def wrap(self,
           primitives_set: core.PrimitiveSet) -> _streaming_aead.StreamingAead:
    return _WrappedStreamingAead(primitives_set)

  def primitive_class(self) -> Type[_streaming_aead.StreamingAead]:
    return _streaming_aead.StreamingAead

  def input_primitive_class(
      self) -> Type[_raw_streaming_aead.RawStreamingAead]:
    return _raw_streaming_aead.RawStreamingAead
