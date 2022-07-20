# Copyright 2019 Google LLC
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

"""This module defines basic exceptions in Tink."""

from tink.cc.pybind import tink_bindings

KNOWN_STATUS_NOT_OK_TYPES = (tink_bindings.PythonTinkException,)


def register_status_not_ok_type(status_not_ok_type):
  global KNOWN_STATUS_NOT_OK_TYPES
  if status_not_ok_type not in KNOWN_STATUS_NOT_OK_TYPES:
    assert issubclass(status_not_ok_type, Exception)
    KNOWN_STATUS_NOT_OK_TYPES += (status_not_ok_type,)


def use_tink_errors(func):
  """Transforms StatusNotOk errors into TinkErrors."""

  def wrapper(*args, **kwargs):
    try:
      return func(*args, **kwargs)
    except KNOWN_STATUS_NOT_OK_TYPES as e:
      raise TinkError(e)
  return wrapper


class TinkError(Exception):
  """Common exception in Tink."""
