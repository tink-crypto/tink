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

"""Tests for _key_types."""

from absl.testing import absltest

from tink_config import _helpers
from tink_config import _key_types


class KeyTypesTest(absltest.TestCase):
  """Sanity tests for _key_types.py.

  This verifies configuration invariants which we always expect to be satisfied.
  For example, each key type which corresponds to a primitive which is in
  PRIVATE_TO_PUBLIC_PRIMITIVE should be correspondingly in
  PRIVATE_TO_PUBLIC_KEY.
  """

  def test_private_keytype_maps_to_public_key_types(self):
    """A test.

    Tests that every item in PRIVATE_TO_PUBLIC_KEY corresponds to an item
    in PRIVATE_TO_PUBLIC_PRIMITIVE.
    """

    for key_types in _key_types.PRIVATE_TO_PUBLIC_KEY.items():
      private_key_type, public_key_type = key_types
      private_primitive = _helpers.primitive_for_keytype(private_key_type)
      public_primitive = _helpers.primitive_for_keytype(public_key_type)
      self.assertIn((private_primitive, public_primitive),
                    _key_types.PRIVATE_TO_PUBLIC_PRIMITIVE.items())

  def test_all_private_keytypes_have_public_keytypes(self):
    """A test.

    Tests that for each pair in PRIVATE_TO_PUBLIC_PRIMITIVE, all corresponding
    key types map to each other.
    """
    for primitives in _key_types.PRIVATE_TO_PUBLIC_PRIMITIVE.items():
      private_primitive, public_primitive = primitives
      for private_key_type in _key_types.KEY_TYPES[private_primitive]:
        public_key_type = _key_types.PRIVATE_TO_PUBLIC_KEY[private_key_type]
        self.assertIn(public_key_type, _key_types.KEY_TYPES[public_primitive])


if __name__ == '__main__':
  absltest.main()
