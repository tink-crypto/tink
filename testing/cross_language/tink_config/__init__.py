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
"""Describes the capabilities of Tink in different languages.

This package describes the state of Tink in all languages. The cross language
tests obtain information from here and use the gRPC servers ensure the
information is correct.

TODO(tholenst): Move all files describing the configuration into this directory,
and add functions to access the information from the outside.
"""

from tink_config import _key_types

# TODO(tholenst): Do not export this, instead export an appropriate function
KEY_TYPES = _key_types.KEY_TYPES
# TODO(tholenst): Do not export this, instead export an appropriate function
SUPPORTED_LANGUAGES = _key_types.SUPPORTED_LANGUAGES
