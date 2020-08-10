/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';

import {EcdsaPrivateKeyManager} from './ecdsa_private_key_manager';
import {EcdsaPublicKeyManager} from './ecdsa_public_key_manager';
import {PublicKeySignWrapper} from './public_key_sign_wrapper';
import {PublicKeyVerifyWrapper} from './public_key_verify_wrapper';

// Static methods and constants for registering with the Registry all instances
// of key types for digital signature supported in a particular release of Tink.
// To register all key types from the current Tink release one can do:
// SignatureConfig.register();

/**
 * Registers key managers for all PublicKeyVerify and PublicKeySign key types
 * from the current Tink release.
 */
export function register() {
  Registry.registerKeyManager(new EcdsaPrivateKeyManager());
  Registry.registerKeyManager(new EcdsaPublicKeyManager());
  Registry.registerPrimitiveWrapper(new PublicKeySignWrapper());
  Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
}

export const VERIFY_PRIMITIVE_NAME: string = 'PublicKeyVerify';

export const ECDSA_PUBLIC_KEY_TYPE: string = EcdsaPublicKeyManager.KEY_TYPE;

export const SIGN_PRIMITIVE_NAME: string = 'PublicKeySign';

export const ECDSA_PRIVATE_KEY_TYPE: string = EcdsaPrivateKeyManager.KEY_TYPE;
