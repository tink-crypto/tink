/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import * as registry from '../internal/registry';

import {EciesAeadHkdfPrivateKeyManager} from './ecies_aead_hkdf_private_key_manager';
import {EciesAeadHkdfPublicKeyManager} from './ecies_aead_hkdf_public_key_manager';
import {HybridDecryptWrapper} from './hybrid_decrypt_wrapper';
import {HybridEncryptWrapper} from './hybrid_encrypt_wrapper';
import {HpkePrivateKeyManager} from './internal/hpke/hpke_private_key_manager';
import {HpkePublicKeyManager} from './internal/hpke/hpke_public_key_manager';

// Static methods and constants for registering with the Registry all instances
// of key types for hybrid encryption and decryption supported in a particular
// release of Tink.
// To register all key types from the current Tink release one can do:
// HybridConfig.register();
// For more information on creation and usage of hybrid encryption instances
// see HybridEncryptFactory (for encryption) and HybridDecryptFactory (for
// decryption).

/**
 * Registers key managers for all HybridEncrypt and HybridDecrypt key types
 * from the current Tink release.
 */
export function register() {
  AeadConfig.register();
  registry.registerKeyManager(new EciesAeadHkdfPrivateKeyManager());
  registry.registerKeyManager(new EciesAeadHkdfPublicKeyManager());
  registry.registerKeyManager(new HpkePrivateKeyManager());
  registry.registerKeyManager(new HpkePublicKeyManager());
  registry.registerPrimitiveWrapper(new HybridEncryptWrapper());
  registry.registerPrimitiveWrapper(new HybridDecryptWrapper());
}

// Suppressing enforced comments since the names are self-explanatory.
// tslint:disable:enforce-comments-on-exported-symbols
export const ENCRYPT_PRIMITIVE_NAME = 'HybridEncrypt';
export const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE: string =
    EciesAeadHkdfPublicKeyManager.KEY_TYPE;
export const HPKE_PUBLIC_KEY_TYPE: string = HpkePublicKeyManager.KEY_TYPE;
export const DECRYPT_PRIMITIVE_NAME = 'HybridDecrypt';
export const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE: string =
    EciesAeadHkdfPrivateKeyManager.KEY_TYPE;
export const HPKE_PRIVATE_KEY_TYPE: string = HpkePrivateKeyManager.KEY_TYPE;
