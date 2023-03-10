/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as registry from '../../../internal/registry';

import * as hpkeKeyTemplates from './hpke_key_templates';
import {HpkePrivateKeyManager} from './hpke_private_key_manager';

/** Registers the private key manager for HPKE */
export function register() {
  registry.registerKeyManager(new HpkePrivateKeyManager());
}

// Suppressing enforced comments since the names are self-explanatory.
// tslint:disable:enforce-comments-on-exported-symbols
export const hpkeP256HkdfSha256Aes128GcmRawKeyTemplate =
    hpkeKeyTemplates.hpkeP256HkdfSha256Aes128GcmRaw();
export const hpkeP256HkdfSha256Aes128GcmKeyTemplate =
    hpkeKeyTemplates.hpkeP256HkdfSha256Aes128Gcm();
export const hpkeP256HkdfSha256Aes256GcmRawKeyTemplate =
    hpkeKeyTemplates.hpkeP256HkdfSha256Aes256GcmRaw();
export const hpkeP256HkdfSha256Aes256GcmKeyTemplate =
    hpkeKeyTemplates.hpkeP256HkdfSha256Aes256Gcm();
export const hpkeP521HkdfSha512Aes256GcmRawKeyTemplate =
    hpkeKeyTemplates.hpkeP521HkdfSha512Aes256GcmRaw();
export const hpkeP521HkdfSha512Aes256GcmKeyTemplate =
    hpkeKeyTemplates.hpkeP521HkdfSha512Aes256Gcm();
