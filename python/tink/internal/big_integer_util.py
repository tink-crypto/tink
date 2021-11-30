# Copyright 2021 Google LLC
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
"""This module contains some utility functions for big integers."""


def num_to_bytes(n: int) -> bytes:
  """Converts a non-negative n into an unsigned big integer in big-endian."""
  if n < 0:
    raise OverflowError("number can't be negative")
  if n == 0:
    return b'\x00'
  return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
