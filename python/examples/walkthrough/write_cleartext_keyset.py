# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Example to showcase how to serialize a keyset as a cleartext."""
# [START tink_walkthrough_write_cleartext_keyset]
from typing import TextIO

import tink

from tink import cleartext_keyset_handle


def WriteKeyset(keyset: tink.KeysetHandle, text_io_stream: TextIO) -> None:
  """Serializes a keyset to JSON-serialized and writes it to text_io_stream.

  Args:
    keyset: Handle to a keyset to serialize.
    text_io_stream: I/O stream where writng the Keyset to.

  Raises:
    tink.TinkError in case of errors.
  """
  cleartext_keyset_handle.write(tink.JsonKeysetWriter(text_io_stream), keyset)


# [END tink_walkthrough_write_cleartext_keyset]
