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


def validate_all_strings(json_data: Any):
  """Recursivly visits all strings and raises UnicodeEncodeError if invalid."""
  if isinstance(json_data, str):
    # We use encode('utf8') to validate that the string is valid.
    json_data.encode('utf8')
  if isinstance(json_data, list):
    for item in json_data:
      validate_all_strings(item)
  if isinstance(json_data, dict):
    for key, value in json_data.items():
      key.encode('utf8')
      validate_all_strings(value)


def json_loads(json_text: str) -> Any:
  """Does the same as json.loads, but with some additional validation."""
  try:
    json_data = json.loads(json_text)
    validate_all_strings(json_data)
    return json_data
  except json.decoder.JSONDecodeError:
    raise _jwt_error.JwtInvalidError('Failed to parse JSON string')
  except RecursionError:
    raise _jwt_error.JwtInvalidError(
        'Failed to parse JSON string, too many recursions')
  except UnicodeEncodeError:
    raise _jwt_error.JwtInvalidError('invalid character')
