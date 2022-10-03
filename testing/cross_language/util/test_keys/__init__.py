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
"""test_keys package."""

from util.test_keys import _create_test_key
from util.test_keys import _test_keys_container

new_or_stored_key = _create_test_key.new_or_stored_key
new_or_stored_keyset = _create_test_key.new_or_stored_keyset
some_keyset_for_primitive = _create_test_key.some_keyset_for_primitive

TestKeysContainer = _test_keys_container.TestKeysContainer
