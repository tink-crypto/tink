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
"""Tests for tink.python.tink.jwt._json_util."""

from absl.testing import absltest
from tink.jwt import _json_util
from tink.jwt import _jwt_error


class JwtFormatTest(absltest.TestCase):

  def test_json_dumps(self):
    self.assertEqual(
        _json_util.json_dumps({'a': ['b', 1, True, None]}),
        '{"a":["b",1,true,null]}')

  def test_json_loads(self):
    self.assertEqual(
        _json_util.json_loads('{"a":["b",1,true,null]}'),
        {'a': ['b', 1, True, None]})
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _json_util.json_loads('{invalid')

  def test_json_loads_recursion(self):
    num_recursions = 1000
    recursive_json = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _json_util.json_loads(recursive_json)

  def test_json_loads_with_invalid_utf16(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _json_util.json_loads(u'{"a":{"b":{"c":"\\uD834"}}}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _json_util.json_loads(u'{"\\uD834":"b"}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _json_util.json_loads(u'{"a":["a",{"b":["c","\\uD834"]}]}')


if __name__ == '__main__':
  absltest.main()
