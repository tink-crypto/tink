/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbMessage, PbOutputPrefixType} from '../../internal/proto';

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
    value: unknown, type: new (...args: never[]) => T): T;
// For classes exported via ts_library_from_closure.
// tslint:disable-next-line:no-any
export function assertInstanceof<T>(value: unknown, type: any): any;
export function assertInstanceof<T>(
    value: unknown, type: new (...args: never[]) => unknown) {
  expect(value instanceof type)
      .withContext(`${value} should be an instance of ${type}`)
      .toBe(true);
  return value;
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
    enabled: boolean = true): PbKeysetKey {
  const key = new PbKeysetKey();
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

/** Asserts that two protos are equal. */
export function assertMessageEquals<T extends PbMessage>(m1: T, m2: T) {
  expect(PbMessage.equals(m1, m2)).toBeTrue();
}
