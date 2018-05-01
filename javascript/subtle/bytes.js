// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.subtle.Bytes');

/**
 * Does near constant time byte array comparison.
 * @param {!Uint8Array} ba1 The first bytearray to check.
 * @param {!Uint8Array} ba2 The second bytearray to check.
 * @return {boolean} If the array are equal.
 */
const compareByteArray = function(ba1, ba2) {
  if (ba1.length !== ba2.length) {
    return false;
  }
  var yes = 1;
  for (var i = 0; i < ba1.length; i++) {
    yes &= !(ba1[i] ^ ba2[i]) | 0;
  }
  return yes == 1;
};

exports = {compareByteArray};
