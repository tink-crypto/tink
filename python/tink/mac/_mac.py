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
"""This module defines the interface for MACs (Message Authentication Codes)."""

import abc


class Mac(metaclass=abc.ABCMeta):
  """Interface for MACs (Message Authentication Codes).

  This interface should be used for authentication only, and not for other
  purposes (e.g., it should not be used to generate pseudorandom bytes).
  """

  @abc.abstractmethod
  def compute_mac(self, data: bytes) -> bytes:
    """Computes the message authentication code (MAC) for data.

    Args:
      data: bytes, the input data.
    Returns:
      The resulting MAC as bytes.
    Raises:
      google3.third_party.tink.python.tink.tink_error.TinkError if the
      computation fails.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    """Verifies if mac is a correct authentication code (MAC) for data.

    Args:
      mac_value: bytes. The mac to be checked.
      data: bytes. The data to be checked.
    Raises:
      google3.third_party.tink.python.tink.tink_error.TinkError if the
      verification fails.
    """
    raise NotImplementedError()
