// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////
import 'jasmine';
import {PbKeyData, PbKeyset, PbKeyStatusType, PbOutputPrefixType} from '../../internal/proto';

/**
 * Returns its input type-narrowed not to be null or undefined. Throws a failed
 * test assertion if it's null or undefined at runtime.
 */
export function assertExists<T>(value: T): NonNullable<T> {
  expect(value).toBeDefined();
  expect(value).not.toBeNull();
  return value as NonNullable<T>;
}

/**
 * Returns its input type-narrowed to a particular type. Throws a failed test
 * assertion if it isn't that type at runtime.
 */
export function assertInstanceof<T>(
    value: unknown, type: new (...args: never[]) => T): T {
  expect(value instanceof type)
      .withContext(`${value} should be an instance of ${type}`)
      .toBe(true);
  return value as T;
}

/**
 * Creates a key for testing purposes. Generates a new key with id, output
 * prefix type and status given by optional arguments. The default values are
 * the following: id = 0x12345678, output prefix type = TINK, and status =
 * ENABLED.
 *
 *
 */
export function createKey(
    keyId: number = 305419896, legacy: boolean = false,
    enabled: boolean = true): PbKeyset.Key {
  const key = new PbKeyset.Key();
  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }
  if (legacy) {
    key.setOutputPrefixType(PbOutputPrefixType.LEGACY);
  } else {
    key.setOutputPrefixType(PbOutputPrefixType.TINK);
  }
  key.setKeyId(keyId);
  const keyData = (new PbKeyData())
                      .setTypeUrl('someTypeUrl')
                      .setValue(new Uint8Array(10))
                      .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  key.setKeyData(keyData);
  return key;
}

/**
 * Returns a valid PbKeyset whose primary key has id equal to 1.
 *
 *
 */
export function createKeyset(keysetSize: number = 20): PbKeyset {
  const keyset = new PbKeyset();
  for (let i = 0; i < keysetSize; i++) {
    const key = createKey(
        /* legacy = */
        i + 1, i % 2 < 1,
        /* enabled = */
        i % 4 < 2);
    keyset.addKey(key);
  }
  keyset.setPrimaryKeyId(1);
  return keyset;
}
