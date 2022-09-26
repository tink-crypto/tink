# Copyright 2022 Google LLC
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
"""Helper functions to access the information in this module.
"""

from typing import Any, List

from tink_config import _key_types

_TYPE_URL_PREFIX = 'type.googleapis.com/google.crypto.tink.'


def all_key_types() -> List[str]:
  """Returns all key types which Tink currently knows in short format.

  The related TypeUrl equals the short format returned here, but prefixed with
  type.googleapis.com/google.crypto.tink.
  """
  result = []
  for key_types_for_single_primitive in _key_types.KEY_TYPES.values():
    result += key_types_for_single_primitive
  return result


def key_types_for_primitive(p: Any) -> List[str]:
  """Returns all key types for the given primitive which Tink currently has.

  The related TypeUrl equals the short format returned here, but prefixed with
  type.googleapis.com/google.crypto.tink.
  Args:
    p: The class of the primitive (e.g. tink.Aead)
  Returns:
    The list of key types (e.g. ['AesGcmKey', 'AesEaxKey'])
  """
  return list(_key_types.KEY_TYPES[p])


def key_type_from_type_url(type_url: str) -> str:
  """Returns the key type from a given TypeUrl, assuming that the value.

  If the TypeUrl is invalid throws an exception.
  Args:
    type_url: Fpr example type.googleapis.com/google.crypto.tink.AesGcmKey
  Returns:
    The stripped version (e.g. AesGcmKey)
  Raises:
    ValueError if the type url is unknown.
  """
  if not type_url.startswith(_TYPE_URL_PREFIX):
    raise ValueError('Invalid type_url: ' + type_url)
  # removeprefix does not yet exist in all our supported python versions.
  stripped_type_url = type_url[len(_TYPE_URL_PREFIX):]
  if stripped_type_url not in all_key_types():
    raise ValueError('type_url for unknown key type: ' + stripped_type_url)
  return stripped_type_url
