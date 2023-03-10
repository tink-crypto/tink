/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as registry from '../../../internal/registry';

import {HpkePublicKeyManager} from './hpke_public_key_manager';

/** Registers the public key manager for HPKE */
export function register() {
  registry.registerKeyManager(new HpkePublicKeyManager());
}
