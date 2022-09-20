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
"""Defines an Invalid JWT Error."""

import json
from typing import Any

from tink.jwt import _jwt_error


def json_dumps(json_data: Any) -> str:
  return json.dumps(json_data, separators=(',', ':'))


def _validate_str(value: str) -> None:
  """Uses encode('utf8') to check if value is a valid string."""
  _ = value.encode('utf8')


def _validate_value(value: Any) -> None:
  """Validates strings in a JSON object value."""
  # We don't need to check strings inside dicts, because json.loads will call
  # _dict_with_validation for these.
  if isinstance(value, str):
    _validate_str(value)
  if isinstance(value, list):
    for item in value:
      if isinstance(item, str):
        _validate_str(item)


def _dict_with_validation(pairs):
  """Validates pairs and returns a dict."""
  keys = set()
  for key, value in pairs:
    _validate_str(key)
    if key in keys:
      raise _jwt_error.JwtInvalidError(
          'Failed to parse JSON string, duplicated key')
    keys.add(key)
    _validate_value(value)
  return dict(pairs)


def json_loads(json_text: str) -> Any:
  """Does the same as json.loads, but with some additional validation."""
  try:
    return json.loads(json_text, object_pairs_hook=_dict_with_validation)
  except json.decoder.JSONDecodeError:
    raise _jwt_error.JwtInvalidError('Failed to parse JSON string')
  except RecursionError:
    raise _jwt_error.JwtInvalidError(
        'Failed to parse JSON string, too many recursions')
  except UnicodeEncodeError:
    raise _jwt_error.JwtInvalidError('invalid character')
