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

from typing import Any, Iterable, List

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
  """Returns the key type from a given TypeUrl.

  If the TypeUrl is invalid throws an exception.
  Args:
    type_url: For example 'type.googleapis.com/google.crypto.tink.AesGcmKey'
  Returns:
    The stripped version (e.g. AesGcmKey)
  Raises:
    ValueError if the type url is unknown or in a bad format.
  """
  if not type_url.startswith(_TYPE_URL_PREFIX):
    raise ValueError('Invalid type_url: ' + type_url)
  # removeprefix does not yet exist in all our supported python versions.
  key_type = type_url[len(_TYPE_URL_PREFIX):]
  if key_type not in all_key_types():
    raise ValueError('key type unknown: ' + key_type)
  return key_type


def supported_languages_for_key_type(key_type: str) -> List[str]:
  """Returns the list of supported languages for a given KeyType.

    Throws an except if the key type is unkonwn.
  Args:
    key_type: The shortened type URL (e.g. 'AesGcmKey')
  Returns:
    The list of languages which this key type supportes.
  Raises:
    ValueError if the key type is unknown.
  """
  if key_type not in all_key_types():
    raise ValueError('key_type unknown: ' + key_type)
  return _key_types.SUPPORTED_LANGUAGES[key_type]


def supported_languages_for_primitive(p: Any) -> List[str]:
  """Returns the list of languages which support a primitive.

    Throws an except if the key type is unkonwn.
  Args:
    p: The Primitive
  Returns:
    The list of languages which this primitive supportes.
  Raises:
    ValueError if the key type is unknown.
  """
  result = set()
  for key_type in key_types_for_primitive(p):
    result.update(set(supported_languages_for_key_type(key_type)))
  return list(result)


def all_primitives() -> Iterable[Any]:
  """Returns all the primitive types (such as tink.aead.Aead)."""
  return [p for p, _ in _key_types.KEY_TYPES.items()]


def primitive_for_keytype(key_type: str) -> Any:
  """Returns the primitive for the given key type."""

  for p, key_types in _key_types.KEY_TYPES.items():
    if key_type in key_types:
      return p
  raise ValueError('Unknown key type: ' + key_type)
