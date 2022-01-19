/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead';
import {AeadConfig} from '../aead/aead_config';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {AesCtrHmacAeadKeyManager} from '../aead/aes_ctr_hmac_aead_key_manager';
import {SecurityException} from '../exception/security_exception';
import * as HybridConfig from '../hybrid/hybrid_config';
import {HybridKeyTemplates} from '../hybrid/hybrid_key_templates';
import {Mac} from '../mac';
import {EncryptThenAuthenticate} from '../subtle/encrypt_then_authenticate';
import {assertExists, assertInstanceof} from '../testing/internal/test_utils';

import * as KeyManager from './key_manager';
import * as PrimitiveSet from './primitive_set';
import {PrimitiveWrapper} from './primitive_wrapper';
import {PbAesCtrHmacAeadKey, PbAesCtrHmacAeadKeyFormat, PbAesCtrKey, PbAesCtrKeyFormat, PbAesCtrParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbHashType, PbHmacKeyFormat, PbHmacParams, PbKeyData, PbKeyTemplate, PbMessage} from './proto';
import * as Registry from './registry';
import {Constructor} from './util';

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

describe('registry test', function() {
  afterEach(function() {
    Registry.reset();
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerPrimitiveWrapper method
  it('register primitive wrapper, overwriting with same class', function() {
    Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
        new DummyPrimitive1Impl1(), DummyPrimitive1));
    Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
        new DummyPrimitive1Impl2(), DummyPrimitive1));
  });

  it('register primitive wrapper, overwriting with different class',
     function() {
       class DummyPrimitiveWrapper1Alternative implements
           PrimitiveWrapper<DummyPrimitive1> {
         wrap(): DummyPrimitive1 {
           throw new Error();
         }

         getPrimitiveType() {
           return DummyPrimitive1;
         }
       }
       Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
           new DummyPrimitive1Impl1(), DummyPrimitive1));
       try {
         Registry.registerPrimitiveWrapper(
             new DummyPrimitiveWrapper1Alternative());
         fail('An exception should be thrown.');
       } catch (e: any) {
         expect(e.toString())
             .toBe(
                 'SecurityException: primitive wrapper for type ' +
                 DummyPrimitive1 +
                 ' has already been registered and cannot be overwritten');
       }
     });

  /////////////////////////////////////////////////////////////////////////////
  // tests for wrap method
  it('wrap, should work', function() {
    const p1 = new DummyPrimitive1Impl1();
    const p2 = new DummyPrimitive2Impl();
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper1(p1, DummyPrimitive1));
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper2(p2, DummyPrimitive2));

    expect(Registry.wrap(new PrimitiveSet.PrimitiveSet(DummyPrimitive1)))
        .toBe(p1);
    expect(Registry.wrap(new PrimitiveSet.PrimitiveSet(DummyPrimitive2)))
        .toBe(p2);
  });

  it('wrap, not registered primitive type', function() {
    expect(() => {
      Registry.wrap(new PrimitiveSet.PrimitiveSet(DummyPrimitive1));
    }).toThrowError('no primitive wrapper found for type ' + DummyPrimitive1);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerKeyManager  method
  it('register key manager, overwriting attempt', function() {
    const keyType = 'someKeyType';

    try {
      Registry.registerKeyManager(new DummyKeyManager1(keyType));
      Registry.registerKeyManager(new DummyKeyManager2(keyType));
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.keyManagerOverwrittingAttempt(keyType));
      return;
    }
    fail('An exception should be thrown.');
  });

  // Testing newKeyAllowed behavior -- should hold the most restrictive setting.
  it('register key manager, more restrictive new key allowed',
     async function() {
       const keyType = 'someTypeUrl';
       const keyManager1 = new DummyKeyManager1(keyType);
       const keyTemplate = new PbKeyTemplate().setTypeUrl(keyType);

       // Register the key manager with new_key_allowed and test that it is
       // possible to create a new key data.
       Registry.registerKeyManager(keyManager1);
       await Registry.newKeyData(keyTemplate);

       // Restrict the key manager and test that new key data cannot be created.
       Registry.registerKeyManager(keyManager1, false);
       try {
         await Registry.newKeyData(keyTemplate);
       } catch (e: any) {
         expect(e.toString()).toBe(ExceptionText.newKeyForbidden(keyType));
         return;
       }
       fail('An exception should be thrown.');
     });

  it('register key manager, less restrictive new key allowed',
     async function() {
       const keyType = 'someTypeUrl';
       const keyManager1 = new DummyKeyManager1(keyType);
       const keyTemplate = new PbKeyTemplate().setTypeUrl(keyType);

       Registry.registerKeyManager(keyManager1, false);

       // Re-registering key manager with less restrictive setting should not be
       // possible and the restriction has to be still true (i.e. new key data
       // cannot be created).
       try {
         Registry.registerKeyManager(keyManager1);
         fail('An exception should be thrown.');
       } catch (e: any) {
         expect(e.toString())
             .toBe(ExceptionText.prohibitedChangeToLessRestricted(
                 keyManager1.getKeyType()));
       }
       try {
         await Registry.newKeyData(keyTemplate);
       } catch (e: any) {
         expect(e.toString()).toBe(ExceptionText.newKeyForbidden(keyType));
         return;
       }
       fail('An exception should be thrown.');
     });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyManager method
  it('get key manager, should work', function() {
    const numberOfKeyManagers = 10;
    const keyManagers1 = [];
    const keyManagers2 = [];
    for (let i = 0; i < numberOfKeyManagers; i++) {
      keyManagers1.push(new DummyKeyManager1('someKeyType' + i.toString()));
      keyManagers2.push(new DummyKeyManager2('otherKeyType' + i.toString()));

      Registry.registerKeyManager(keyManagers1[i]);
      Registry.registerKeyManager(keyManagers2[i]);
    }

    let result;
    for (let i = 0; i < numberOfKeyManagers; i++) {
      result = Registry.getKeyManager(keyManagers1[i].getKeyType());
      expect(result).toEqual(keyManagers1[i]);

      result = Registry.getKeyManager(keyManagers2[i].getKeyType());
      expect(result).toEqual(keyManagers2[i]);
    }
  });

  it('get key manager, not registered key type', function() {
    const keyType = 'some_key_type';

    try {
      Registry.getKeyManager(keyType);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.notRegisteredKeyType(keyType));
      return;
    }
    fail('An exception should be thrown.');
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKeyData method
  it('new key data, no manager for given key type', async function() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const differentKeyType = 'otherKeyType';
    const keyTemplate = new PbKeyTemplate().setTypeUrl(differentKeyType);

    Registry.registerKeyManager(keyManager1);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.notRegisteredKeyType(differentKeyType));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key data, new key disallowed', async function() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const keyTemplate =
        new PbKeyTemplate().setTypeUrl(keyManager1.getKeyType());

    Registry.registerKeyManager(keyManager1, false);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.newKeyForbidden(keyManager1.getKeyType()));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key data, new key allowed', async function() {
    const keyTypes: string[] = [];
    for (let i = 0; i < 10; i++) {
      keyTypes.push('someKeyType' + i.toString());
    }

    const keyTypesLength = keyTypes.length;
    for (let i = 0; i < keyTypesLength; i++) {
      Registry.registerKeyManager(new DummyKeyManager1(keyTypes[i]), true);
    }

    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate().setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      expect(result.getTypeUrl()).toBe(keyTypes[i]);
    }
  });

  it('new key data, new key is allowed automatically', async function() {
    const keyTypes: string[] = [];
    for (let i = 0; i < 10; i++) {
      keyTypes.push('someKeyType' + i.toString());
    }

    const keyTypesLength = keyTypes.length;
    for (let i = 0; i < keyTypesLength; i++) {
      Registry.registerKeyManager(new DummyKeyManager1(keyTypes[i]));
    }

    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate().setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      expect(result.getTypeUrl()).toBe(keyTypes[i]);
    }
  });

  it('new key data, with aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    // Checks that correct AES CTR HMAC AEAD key was returned.
    const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
        keyTemplate.getValue_asU8());
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue_asU8());
    // Check AES CTR key.
    expect(keyFormat.getAesCtrKeyFormat()?.getKeySize())
        .toBe(key.getAesCtrKey()?.getKeyValue_asU8().length);
    expect(keyFormat.getAesCtrKeyFormat()?.getParams())
        .toEqual(key.getAesCtrKey()?.getParams());
    // Check HMAC key.
    expect(keyFormat.getHmacKeyFormat()?.getKeySize())
        .toBe(key.getHmacKey()?.getKeyValue_asU8().length);
    expect(keyFormat.getHmacKeyFormat()?.getParams())
        .toEqual(key.getHmacKey()?.getParams());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method
  it('new key, no manager for given key type', async function() {
    const notRegisteredKeyType = 'not_registered_key_type';
    const keyTemplate = new PbKeyTemplate().setTypeUrl(notRegisteredKeyType);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.notRegisteredKeyType(notRegisteredKeyType));
    }
  });

  it('new key, new key disallowed', async function() {
    const keyManager = new DummyKeyManagerForNewKeyTests('someKeyType');
    const keyTemplate = new PbKeyTemplate().setTypeUrl(keyManager.getKeyType());
    Registry.registerKeyManager(keyManager, /* opt_newKeyAllowed = */ false);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.newKeyForbidden(keyManager.getKeyType()));
    }
  });

  it('new key, should work', async function() {
    const keyTypes: string[] = [];
    const newKeyMethodResult: Uint8Array[] = [];
    const keyTypesLength = 10;

    // Add some keys to Registry.
    for (let i = 0; i < keyTypesLength; i++) {
      keyTypes.push('someKeyType' + i.toString());
      newKeyMethodResult.push(new Uint8Array([i + 1]));

      Registry.registerKeyManager(
          new DummyKeyManagerForNewKeyTests(keyTypes[i], newKeyMethodResult[i]),
          /* newKeyAllowed = */ true);
    }

    // For every keyType verify that it calls new key method of the
    // corresponding KeyManager (KeyFactory).
    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate().setTypeUrl(keyTypes[i]);

      const key =
          assertInstanceof(await Registry.newKey(keyTemplate), PbAesCtrKey);

      // The new key method of DummyKeyFactory returns an AesCtrKey which
      // KeyValue is set to corresponding value in newKeyMethodResult.
      expect(key.getKeyValue_asU8()).toBe(newKeyMethodResult[i]);
    }
  });
  it('new key, with aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();

    const key = assertInstanceof(
        await Registry.newKey(keyTemplate), PbAesCtrHmacAeadKey);

    // Checks that correct AES CTR HMAC AEAD key was returned.
    const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
        keyTemplate.getValue_asU8());
    // Check AES CTR key.
    expect(keyFormat.getAesCtrKeyFormat()?.getKeySize())
        .toBe(key.getAesCtrKey()?.getKeyValue_asU8().length);
    expect(keyFormat.getAesCtrKeyFormat()?.getParams())
        .toEqual(key.getAesCtrKey()?.getParams());
    // Check HMAC key.
    expect(keyFormat.getHmacKeyFormat()?.getKeySize())
        .toBe(key.getHmacKey()?.getKeyValue_asU8().length);
    expect(keyFormat.getHmacKeyFormat()?.getParams())
        .toEqual(key.getHmacKey()?.getParams());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method
  it('get primitive, different key types', async function() {
    const keyDataType = 'key_data_key_type_url';
    const anotherType = 'another_key_type_url';
    const keyData = new PbKeyData().setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(Aead, keyData, anotherType);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.keyTypesAreNotMatching(keyDataType, anotherType));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('get primitive, without defining key type', async function() {
    // Get primitive from key proto without key type.
    try {
      await Registry.getPrimitive(Aead, new PbHmacParams());
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.keyTypeNotDefined());
    }
  });

  it('get primitive, missing key manager', async function() {
    const keyDataType = 'key_data_key_type_url';
    const keyData = new PbKeyData().setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(Aead, keyData);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.notRegisteredKeyType(keyDataType));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('get primitive, from aes ctr hmac aead key data', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    const primitive =
        await Registry.getPrimitive(manager.getPrimitiveType(), keyData);
    expect(primitive instanceof EncryptThenAuthenticate).toBe(true);
  });

  it('get primitive, from aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue_asU8());

    const primitive = await Registry.getPrimitive(
        manager.getPrimitiveType(), key, keyData.getTypeUrl());
    expect(primitive instanceof EncryptThenAuthenticate).toBe(true);
  });

  it('get primitive, mac from aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue_asU8());

    try {
      await Registry.getPrimitive(Mac, key, keyData.getTypeUrl());
    } catch (e: any) {
      expect(e.toString().includes(ExceptionText.getPrimitiveBadPrimitive()))
          .toBe(true);
      return;
    }
    fail('An exception should be thrown.');
  });

  describe('get public key data', function() {
    it('not private key factory', function() {
      AeadConfig.register();
      const notPrivateTypeUrl = AeadConfig.AES_GCM_TYPE_URL;
      try {
        Registry.getPublicKeyData(notPrivateTypeUrl, new Uint8Array(8));
        fail('An exception should be thrown.');
      } catch (e: any) {
        expect(e.toString())
            .toBe(ExceptionText.notPrivateKeyFactory(notPrivateTypeUrl));
      }
    });

    it('invalid private key proto serialization', function() {
      HybridConfig.register();
      const typeUrl = HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE;
      try {
        Registry.getPublicKeyData(typeUrl, new Uint8Array(10));
        fail('An exception should be thrown.');
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.couldNotParse(typeUrl));
      }
    });

    it('should work', async function() {
      HybridConfig.register();
      const privateKeyData = await Registry.newKeyData(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      const privateKey = PbEciesAeadHkdfPrivateKey.deserializeBinary(
          privateKeyData.getValue_asU8());

      const publicKeyData = Registry.getPublicKeyData(
          privateKeyData.getTypeUrl(), privateKeyData.getValue_asU8());
      expect(HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE)
          .toBe(publicKeyData.getTypeUrl());
      expect(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .toBe(publicKeyData.getKeyMaterialType());

      const expectedPublicKey = assertExists(privateKey.getPublicKey());
      const publicKey = PbEciesAeadHkdfPublicKey.deserializeBinary(
          publicKeyData.getValue_asU8());
      expect(publicKey).toEqual(expectedPublicKey);
    });
  });
});

////////////////////////////////////////////////////////////////////////////////
// helper functions and classes for tests
////////////////////////////////////////////////////////////////////////////////

/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  static notImplemented(): string {
    return 'SecurityException: Not implemented yet.';
  }

  static newKeyForbidden(keyType: string): string {
    return 'SecurityException: New key operation is forbidden for key type: ' +
        keyType + '.';
  }

  static notRegisteredKeyType(keyType: string): string {
    return 'SecurityException: Key manager for key type ' + keyType +
        ' has not been registered.';
  }

  static nullKeyManager(): string {
    return 'SecurityException: Key manager cannot be null.';
  }

  static undefinedKeyType(): string {
    return 'SecurityException: Key type has to be defined.';
  }

  static keyManagerOverwrittingAttempt(keyType: string): string {
    return 'SecurityException: Key manager for key type ' + keyType +
        ' has already been registered and cannot be overwritten.';
  }

  static notSupportedKey(givenKeyType: string): string {
    return 'SecurityException: The provided key manager does not support ' +
        'key type ' + givenKeyType + '.';
  }

  static prohibitedChangeToLessRestricted(keyType: string): string {
    return 'SecurityException: Key manager for key type ' + keyType +
        ' has already been registered with forbidden new key operation.';
  }

  static keyTypesAreNotMatching(
      keyTypeFromKeyData: string, keyTypeParam: string): string {
    return 'SecurityException: Key type is ' + keyTypeParam +
        ', but it is expected to be ' + keyTypeFromKeyData + ' or undefined.';
  }

  static keyTypeNotDefined(): string {
    return 'SecurityException: Key type has to be specified.';
  }

  static nullKeysetHandle(): string {
    return 'SecurityException: Keyset handle has to be non-null.';
  }

  static getPrimitiveBadPrimitive(): string {
    return 'Requested primitive type which is not supported by this ' +
        'key manager.';
  }

  static notPrivateKeyFactory(typeUrl: string): string {
    return 'SecurityException: Key manager for key type ' + typeUrl +
        ' does not have a private key factory.';
  }

  static couldNotParse(typeUrl: string): string {
    return 'SecurityException: Input cannot be parsed as ' + typeUrl +
        ' key-proto.';
  }
}

/** Creates AES CTR HMAC AEAD key format which can be used in tests */
function createAesCtrHmacAeadTestKeyTemplate(): PbKeyTemplate {
  const KEY_SIZE = 16;
  const IV_SIZE = 12;
  const TAG_SIZE = 16;

  const keyFormat = new PbAesCtrHmacAeadKeyFormat().setAesCtrKeyFormat(
      new PbAesCtrKeyFormat());
  keyFormat.getAesCtrKeyFormat()?.setKeySize(KEY_SIZE);
  keyFormat.getAesCtrKeyFormat()?.setParams(new PbAesCtrParams());
  keyFormat.getAesCtrKeyFormat()?.getParams()?.setIvSize(IV_SIZE);

  // set HMAC key
  keyFormat.setHmacKeyFormat(new PbHmacKeyFormat());
  keyFormat.getHmacKeyFormat()?.setKeySize(KEY_SIZE);
  keyFormat.getHmacKeyFormat()?.setParams(new PbHmacParams());
  keyFormat.getHmacKeyFormat()?.getParams()?.setHash(PbHashType.SHA1);
  keyFormat.getHmacKeyFormat()?.getParams()?.setTagSize(TAG_SIZE);

  let keyTemplate =
      new PbKeyTemplate()
          .setTypeUrl(
              'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey')
          .setValue(keyFormat.serializeBinary());
  return keyTemplate;
}

// Key factory and key manager classes used in tests

/** @final */
class DummyKeyFactory implements KeyManager.KeyFactory {
  constructor(
      private readonly keyType: string,
      private readonly newKeyMethodResult = new Uint8Array(10)) {}

  /**
   */
  newKey(keyFormat: PbMessage|Uint8Array) {
    const key = new PbAesCtrKey().setKeyValue(this.newKeyMethodResult);
    return key;
  }

  /**
   */
  newKeyData(serializedKeyFormat: Uint8Array) {
    const keyData =
        new PbKeyData()
            .setTypeUrl(this.keyType)
            .setValue(this.newKeyMethodResult)
            .setKeyMaterialType(PbKeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL);

    return keyData;
  }
}

// Primitive abstract types for testing purposes.
abstract class DummyPrimitive1 {
  abstract operation1(): number;
}
abstract class DummyPrimitive2 {
  abstract operation2(): string;
}

// Primitive implementations for testing purposes.
class DummyPrimitive1Impl1 extends DummyPrimitive1 {
  operation1() {
    return 1;
  }
}
class DummyPrimitive1Impl2 extends DummyPrimitive1 {
  operation1() {
    return 2;
  }
}
class DummyPrimitive2Impl extends DummyPrimitive2 {
  operation2() {
    return 'dummy';
  }
}

const DEFAULT_PRIMITIVE_TYPE = Aead;

/** @final */
class DummyKeyManager1 implements KeyManager.KeyManager<DummyPrimitive1> {
  private readonly KEY_FACTORY: KeyManager.KeyFactory;

  constructor(
      private readonly keyType: string,
      private readonly primitive: DummyPrimitive1 = new DummyPrimitive1Impl1(),
      private readonly primitiveType = DummyPrimitive1) {
    this.KEY_FACTORY = new DummyKeyFactory(keyType);
  }

  async getPrimitive(
      primitiveType: Constructor<DummyKeyManager1>, key: PbKeyData|PbMessage) {
    return this.primitive;
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return this.keyType;
  }

  getPrimitiveType(): Constructor<DummyPrimitive1> {
    return this.primitiveType;
  }

  getVersion(): number {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }

  getKeyFactory() {
    return this.KEY_FACTORY;
  }
}

/** @final */
class DummyKeyManager2 implements KeyManager.KeyManager<DummyPrimitive2> {
  private readonly KEY_FACTORY: KeyManager.KeyFactory;

  constructor(
      private readonly keyType: string,
      private readonly primitive: DummyPrimitive2 = new DummyPrimitive2Impl(),
      private readonly primitiveType = DummyPrimitive2) {
    this.KEY_FACTORY = new DummyKeyFactory(keyType);
  }

  async getPrimitive(
      primitiveType: Constructor<DummyKeyManager2>, key: PbKeyData|PbMessage) {
    return this.primitive;
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return this.keyType;
  }

  getPrimitiveType() {
    return this.primitiveType;
  }

  getVersion(): number {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }

  getKeyFactory() {
    return this.KEY_FACTORY;
  }
}

/** @final */
class DummyKeyManagerForNewKeyTests implements KeyManager.KeyManager<string> {
  private readonly KEY_FACTORY: KeyManager.KeyFactory;

  constructor(
      private readonly keyType: string, opt_newKeyMethodResult?: Uint8Array) {
    this.KEY_FACTORY = new DummyKeyFactory(keyType, opt_newKeyMethodResult);
  }

  async getPrimitive(
      primitiveType: Constructor<DummyKeyManagerForNewKeyTests>,
      key: PbKeyData|PbMessage): Promise<string> {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return this.keyType;
  }

  getPrimitiveType(): never {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  getVersion(): never {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  getKeyFactory() {
    return this.KEY_FACTORY;
  }
}

// PrimitiveWrapper classes for testing purposes

/** @final */
class DummyPrimitiveWrapper1 implements PrimitiveWrapper<DummyPrimitive1> {
  constructor(
      private readonly primitive: DummyPrimitive1,
      private readonly primitiveType: Constructor<DummyPrimitive1>) {}

  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<DummyPrimitive1>) {
    return this.primitive;
  }

  getPrimitiveType() {
    return this.primitiveType;
  }
}

/** @final */
class DummyPrimitiveWrapper2 implements PrimitiveWrapper<DummyPrimitive2> {
  constructor(
      private readonly primitive: DummyPrimitive2,
      private readonly primitiveType: Constructor<DummyPrimitive2>) {}

  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<DummyPrimitive2>) {
    return this.primitive;
  }

  getPrimitiveType() {
    return this.primitiveType;
  }
}
