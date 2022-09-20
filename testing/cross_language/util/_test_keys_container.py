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
"""A container to store precomputed keys."""

import textwrap
from typing import Dict

from tink.proto import tink_pb2
from util import key_util


## TODO(tholenst): Move this class in a subdirectory test_key_creation (or so)
class TestKeysContainer():
  """Container for test keys."""

  _map: Dict[str, tink_pb2.Keyset.Key]

  def __init__(self):
    self._map = {}

  def add_key(self, template: str, key: str) -> None:
    """Adds a new key to the list of precomputed keys.

    The arguments need to be in the format produced by key_util.text_format,
    but can be additionally indented and have whitespace (it needs to be in the
    format after calling textwrap.dedent() and strip()).

    The key will be stored in a map keyed by the template, unless a key-value
    pair with this template as key was previously inserted in a call to
    'add_key'.

    Args:
      template: A key template in the format created by key_util.text_format,
        possibly indented, and with additional spaces at the beginning and the
        end.
      key: A key corresponding to the template in the format created by
        key_util.text_format, possibly indented, and with additional spaces.
    """

    dedented_template = textwrap.dedent(template).strip()
    dedented_key = textwrap.dedent(key).strip()
    parsed_template = tink_pb2.KeyTemplate()
    # We parse to check the correctness of the formatting
    key_util.parse_text_format(dedented_template, parsed_template)

    parsed_key = tink_pb2.Keyset.Key()
    key_util.parse_text_format(dedented_key, parsed_key)
    if dedented_template in self._map:
      raise ValueError('Template already present')
    self._map[dedented_template] = parsed_key

  def get_key(self, template: tink_pb2.KeyTemplate) -> tink_pb2.Keyset.Key:
    """Returns a previously stored key for this template."""

    template_text_format = key_util.text_format(template)
    return self._map[template_text_format]
