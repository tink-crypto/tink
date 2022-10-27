/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @fileoverview Registry for KeyManagers.
 *
 * Registry maps supported key types to corresponding KeyManager objects (i.e.
 * the KeyManagers which may instantiate the primitive corresponding to the
 * given key or generate new key of the given type). Keeping KeyManagers for all
 * primitives in a single Registry (rather than having a separate keyManager per
 * primitive) enables modular construction of compound primitives from "simple"
 * ones (e.g. AES-CTR-HMAC AEAD encryption from IND-CPA encryption and MAC).
 *
 * Regular users will not usually work with Registry directly, but via primitive
 * factories, which query Registry for the specific KeyManagers in the
 * background.
 */

import {SecurityException} from '../exception/security_exception';

import * as KeyManager from './key_manager';
import * as PrimitiveSet from './primitive_set';
import {PrimitiveWrapper} from './primitive_wrapper';
import {PbKeyData, PbKeyTemplate, PbMessage} from './proto';
import {bytesAsU8} from './proto_shims';
import {Constructor, isInstanceOf} from './util';

// key managers maps
const typeToManagerMap_ = new Map<string, KeyManager.KeyManager<unknown>>();

const typeToNewKeyAllowedMap_ = new Map<string, boolean>();

// primitive wrappers map
const primitiveTypeToWrapper_ = new Map<unknown, PrimitiveWrapper<unknown>>();

/**
 * Register the given manager for the given key type. Manager must be
 * non-nullptr. New keys are allowed if not specified.
 */
export function registerKeyManager(
    manager: KeyManager.KeyManager<unknown>, opt_newKeyAllowed?: boolean) {
  if (opt_newKeyAllowed === undefined) {
    opt_newKeyAllowed = true;
  }
  if (!manager) {
    throw new SecurityException('Key manager cannot be null.');
  }
  const typeUrl = manager.getKeyType();
  if (typeToManagerMap_.has(typeUrl)) {
    // Cannot overwrite the existing key manager by a new one.
    if (!(typeToManagerMap_.get(typeUrl) instanceof manager.constructor)) {
      throw new SecurityException(
          'Key manager for key type ' + typeUrl +
          ' has already been registered and cannot be overwritten.');
    }

    // It is forbidden to change new_key_allowed from false to true.
    if (!typeToNewKeyAllowedMap_.get(typeUrl) && opt_newKeyAllowed) {
      throw new SecurityException(
          'Key manager for key type ' + typeUrl +
          ' has already been registered with forbidden new key operation.');
    }
    typeToNewKeyAllowedMap_.set(typeUrl, opt_newKeyAllowed);
  }
  typeToManagerMap_.set(typeUrl, manager);
  typeToNewKeyAllowedMap_.set(typeUrl, opt_newKeyAllowed);
}

/**
 * Returns a key manager for the given key type or throws an exception if no
 * such manager found.
 *
 * @param typeUrl -- key type
 *
 */
export function getKeyManager(typeUrl: string): KeyManager.KeyManager<unknown> {
  const res = typeToManagerMap_.get(typeUrl);
  if (!res) {
    throw new SecurityException(
        'Key manager for key type ' + typeUrl + ' has not been registered.');
  }
  return res;
}

/**
 * It finds KeyManager according to key type (which is either given by
 * PbKeyData or given by opt_typeUrl), than calls the corresponding
 * manager's getPrimitive method.
 *
 * Either key is of type PbKeyData or opt_typeUrl must be provided.
 *
 * @param key -- key is either a proto of some key
 *     or key data.
 * @param opt_typeUrl -- key type
 * @this {typeof Registry}
 *
 */
export async function getPrimitive<P>(
    primitiveType: Constructor<P>, key: PbKeyData|PbMessage,
    opt_typeUrl?: string|null): Promise<P> {
  if (key instanceof PbKeyData) {
    if (opt_typeUrl && key.getTypeUrl() != opt_typeUrl) {
      throw new SecurityException(
          'Key type is ' + opt_typeUrl + ', but it is expected to be ' +
          key.getTypeUrl() + ' or undefined.');
    }
    opt_typeUrl = key.getTypeUrl();
  }
  if (!opt_typeUrl) {
    throw new SecurityException('Key type has to be specified.');
  }
  const manager = getKeyManager(opt_typeUrl);
  const primitive = await manager.getPrimitive(primitiveType, key);
  if (!isInstanceOf(primitive, primitiveType)) {
    throw new TypeError('Unexpected type');
  }
  return primitive;
}

/**
 * Generates a new PbKeyData for the specified keyTemplate. It finds a
 * KeyManager given by keyTemplate.typeUrl and calls the newKeyData method of
 * that manager.
 *
 *
 *
 */
export async function newKeyData(keyTemplate: PbKeyTemplate):
    Promise<PbKeyData> {
  const manager = getKeyManagerWithNewKeyAllowedCheck_(keyTemplate);
  return manager.getKeyFactory().newKeyData(bytesAsU8(keyTemplate.getValue()));
}

/**
 * Generates a new key for the specified keyTemplate using the
 * KeyManager determined by typeUrl field of the keyTemplate.
 *
 *
 *
 * @return returns a key proto
 */
export async function newKey(keyTemplate: PbKeyTemplate): Promise<PbMessage> {
  const manager = getKeyManagerWithNewKeyAllowedCheck_(keyTemplate);
  return manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
}

/**
 * Convenience method for extracting the public key data from the private key
 * given by serializedPrivateKey.
 * It looks up a KeyManager identified by typeUrl, which must hold
 * PrivateKeyFactory, and calls getPublicKeyData method of that factory.
 *
 */
export function getPublicKeyData(
    typeUrl: string, serializedPrivateKey: Uint8Array): PbKeyData {
  const manager = getKeyManager(typeUrl);

  // This solution might cause some problems in the future due to Closure
  // compiler optimizations, which may map factory.getPublicKeyData to
  // concrete function.
  const factory = manager.getKeyFactory();
  if (!factory.getPublicKeyData) {
    throw new SecurityException(
        'Key manager for key type ' + typeUrl +
        ' does not have a private key factory.');
  }
  return factory.getPublicKeyData(serializedPrivateKey);
}

/**
 * Resets the registry.
 * After reset the registry is empty, i.e. it contains no key managers.
 *
 * This method is only for testing.
 */
export function reset() {
  typeToManagerMap_.clear();
  typeToNewKeyAllowedMap_.clear();
  primitiveTypeToWrapper_.clear();
}

/**
 * It finds a KeyManager given by keyTemplate.typeUrl and returns it if it
 * allows creating new keys.
 *
 *
 */
function getKeyManagerWithNewKeyAllowedCheck_(keyTemplate: PbKeyTemplate):
    KeyManager.KeyManager<unknown> {
  const keyType = keyTemplate.getTypeUrl();
  const manager = getKeyManager(keyType);
  if (!typeToNewKeyAllowedMap_.get(keyType)) {
    throw new SecurityException(
        'New key operation is forbidden for ' +
        'key type: ' + keyType + '.');
  }
  return manager;
}

/**
 * Tries to register a primitive wrapper.
 */
export function registerPrimitiveWrapper<P>(wrapper: PrimitiveWrapper<P>) {
  if (!wrapper) {
    throw new SecurityException('primitive wrapper cannot be null');
  }
  const primitiveType = wrapper.getPrimitiveType();
  if (!primitiveType) {
    throw new SecurityException('primitive wrapper cannot be undefined');
  }
  if (primitiveTypeToWrapper_.has(primitiveType)) {
    // Cannot overwrite the existing key manager by a new one.
    if (!(primitiveTypeToWrapper_.get(primitiveType) instanceof
          wrapper.constructor)) {
      throw new SecurityException(
          'primitive wrapper for type ' + primitiveType +
          ' has already been registered and cannot be overwritten');
    }
  }
  primitiveTypeToWrapper_.set(primitiveType, wrapper);
}

/**
 * Wraps a PrimitiveSet and returns a single instance.
 */
export function wrap<P>(primitiveSet: PrimitiveSet.PrimitiveSet<P>): P {
  if (!primitiveSet) {
    throw new SecurityException('primitive set cannot be null.');
  }
  const primitiveType = primitiveSet.getPrimitiveType();
  const wrapper = primitiveTypeToWrapper_.get(primitiveType);
  if (!wrapper) {
    throw new SecurityException(
        'no primitive wrapper found for type ' + primitiveType);
  }
  const primitive = wrapper.wrap(primitiveSet);
  if (!isInstanceOf(primitive, primitiveType)) {
    throw new TypeError('Unexpected type');
  }
  return primitive;
}
