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

goog.module('tink.PrimitiveSetTest');
goog.setTestOnly('tink.PrimitiveSetTest');

const PrimitiveSet = goog.require('tink.PrimitiveSet');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  /////////////////////////////////////////////////////////////////////////////
  // tests for addPrimitive method
  async testAddPrimitive() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    try {
      await primitiveSet.addPrimitive(null, null);
    } catch (e) {
      assertEquals(
          'CustomError: PrimitiveSet -- addPrimitive: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  async testGetPrimitives() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    try {
      await primitiveSet.getPrimitives(new Uint8Array());
    } catch (e) {
      assertEquals(
          'CustomError: PrimitiveSet -- getPrimitives: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getRawPrimitives method
  async testGetRawPrimitives() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    try {
      await primitiveSet.getRawPrimitives();
    } catch (e) {
      assertEquals(
          'CustomError: PrimitiveSet -- getRawPrimitives: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for setPrimary method
  async testSetPrimary() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    try {
      await primitiveSet.setPrimary(null);
    } catch (e) {
      assertEquals(
          'CustomError: PrimitiveSet -- setPrimary: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimary method
  async testGetPrimary() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    try {
      await primitiveSet.getPrimary();
    } catch (e) {
      assertEquals(
          'CustomError: PrimitiveSet -- getPrimary: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },
});
