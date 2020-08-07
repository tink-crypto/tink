/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';
import {AesCtrHmacAeadKeyManager} from './aes_ctr_hmac_aead_key_manager';
import {AesCtrHmacAeadKeyTemplates} from './aes_ctr_hmac_aead_key_templates';

export function register() {
  Registry.registerKeyManager(new AesCtrHmacAeadKeyManager());
}

export const aes128CtrHmacSha256KeyTemplate =
    AesCtrHmacAeadKeyTemplates.aes128CtrHmacSha256;
export const aes256CtrHmacSha256KeyTemplate =
    AesCtrHmacAeadKeyTemplates.aes256CtrHmacSha256;
