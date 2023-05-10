/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as registry from '../internal/registry';

import {HmacKeyManager} from './hmac_key_manager';
import * as macKeyTemplates from './mac_key_templates';

/** Registers the HMAC key manager */
export function register() {
  registry.registerKeyManager(new HmacKeyManager());
}

// Suppressing enforced comments since the names are self-explanatory.
// tslint:disable:enforce-comments-on-exported-symbols
export const hmacSha256Tag128KeyTemplate = macKeyTemplates.hmacSha256Tag128();
export const hmacSha256Tag256KeyTemplate = macKeyTemplates.hmacSha256Tag256();
export const hmacSha512Tag256KeyTemplate = macKeyTemplates.hmacSha512Tag256();
export const hmacSha512Tag512KeyTemplate = macKeyTemplates.hmacSha512Tag512();
