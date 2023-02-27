/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeKeyFormat, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey} from '../../../internal/proto';
import * as bytes from '../../../subtle/bytes';

import * as hpkeValidators from './hpke_validators';

const VERSION = 0;

/** Values taken from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A */
const validPublicKeyBytes = bytes.fromHex(
    '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0');
const validPrivateKeyBytes = bytes.fromHex(
    'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2');

function createValidParams() {
  return new PbHpkeParams()
      .setKem(PbHpkeKem.DHKEM_P256_HKDF_SHA256)
      .setKdf(PbHpkeKdf.HKDF_SHA256)
      .setAead(PbHpkeAead.AES_128_GCM);
}

function createPublicKey(params?: PbHpkeParams) {
  return new PbHpkePublicKey()
      .setVersion(VERSION)
      .setParams(params)
      .setPublicKey(validPublicKeyBytes);
}

function createPrivateKey(publicKey?: PbHpkePublicKey) {
  return new PbHpkePrivateKey()
      .setVersion(VERSION)
      .setPublicKey(publicKey)
      .setPrivateKey(validPrivateKeyBytes);
}

describe('hpke validators test', () => {
  it('validate params should work', () => {
    hpkeValidators.validateParams(createValidParams());
  });
  it('validate params fails for unknown kem', () => {
    const unknownKemParams: PbHpkeParams =
        createValidParams().setKem(PbHpkeKem.KEM_UNKNOWN);
    try {
      hpkeValidators.validateParams(unknownKemParams);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KEM identifier.');
    }
  });
  it('validate params fails for unknown kdf', () => {
    const unknownKdfParams: PbHpkeParams =
        createValidParams().setKdf(PbHpkeKdf.KDF_UNKNOWN);
    try {
      hpkeValidators.validateParams(unknownKdfParams);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KDF identifier.');
    }
  });
  it('validate params fails for unknown aead', () => {
    const unknownAeadParams: PbHpkeParams =
        createValidParams().setAead(PbHpkeAead.AEAD_UNKNOWN);
    try {
      hpkeValidators.validateParams(unknownAeadParams);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown AEAD identifier.');
    }
  });

  it('validate key format should work', () => {
    const validKeyFormat = new PbHpkeKeyFormat().setParams(createValidParams());
    hpkeValidators.validateKeyFormat(validKeyFormat);
  });
  it('validate key format, missing params', () => {
    const invalidKeyFormat = new PbHpkeKeyFormat();
    try {
      hpkeValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid key format - missing key params.');
    }
  });
  it('validate key format, invalid params', () => {
    const invalidKeyFormat: PbHpkeKeyFormat = new PbHpkeKeyFormat().setParams(
        createValidParams().setKem(PbHpkeKem.KEM_UNKNOWN));
    try {
      hpkeValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KEM identifier.');
    }
  });

  it('validate public key, should work', () => {
    const validPublicKey: PbHpkePublicKey =
        createPublicKey(createValidParams());
    hpkeValidators.validatePublicKey(validPublicKey, VERSION);
  });
  it('validate public key, missing params', () => {
    const invalidPublicKey: PbHpkePublicKey = createPublicKey();
    try {
      hpkeValidators.validatePublicKey(invalidPublicKey, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid public key - missing key params.');
    }
  });
  it('validate public key, missing public key value', () => {
    const invalidPublicKey: PbHpkePublicKey =
        new PbHpkePublicKey().setVersion(VERSION).setParams(
            createValidParams());
    try {
      hpkeValidators.validatePublicKey(invalidPublicKey, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid public key - missing public key value.');
    }
  });
  it('validate public key, invalid params', () => {
    const invalidPublicKey: PbHpkePublicKey = createPublicKey().setParams(
        createValidParams().setKem(PbHpkeKem.KEM_UNKNOWN));
    try {
      hpkeValidators.validatePublicKey(invalidPublicKey, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KEM identifier.');
    }
  });
  it('validate public key, version out of bounds', () => {
    const invalidPublicKey: PbHpkePublicKey = createPublicKey().setVersion(1);
    try {
      hpkeValidators.validatePublicKey(invalidPublicKey, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Version is out of bound, must be between 0 and ' +
              VERSION.toString() + '.');
    }
  });

  it('validate private key, should work', () => {
    const validPublicKey: PbHpkePublicKey =
        createPublicKey(createValidParams());
    const validPrivateKey: PbHpkePrivateKey = createPrivateKey(validPublicKey);
    hpkeValidators.validatePrivateKey(validPrivateKey, VERSION, VERSION);
  });

  it('validate private key, missing public key', () => {
    const invalidPrivateKey: PbHpkePrivateKey = createPrivateKey();
    try {
      hpkeValidators.validatePrivateKey(invalidPrivateKey, VERSION, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid private key - missing public key field.');
    }
  });

  it('validate private key, missing private key value', () => {
    const publicKey: PbHpkePublicKey = createPublicKey(createValidParams());
    const invalidPrivateKey: PbHpkePrivateKey =
        new PbHpkePrivateKey().setVersion(VERSION).setPublicKey(publicKey);
    try {
      hpkeValidators.validatePrivateKey(invalidPrivateKey, VERSION, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid private key - missing private key value.');
    }
  });

  it('validate private key, version out of bounds', () => {
    const publicKey: PbHpkePublicKey = createPublicKey(createValidParams());
    const invalidPrivateKey: PbHpkePrivateKey =
        createPrivateKey(publicKey).setVersion(1);
    try {
      hpkeValidators.validatePrivateKey(invalidPrivateKey, VERSION, VERSION);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Version is out of bound, must be between 0 and ' +
              VERSION.toString() + '.');
    }
  });
});
