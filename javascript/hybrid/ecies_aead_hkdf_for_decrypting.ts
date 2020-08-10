/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';
import {EciesAeadHkdfPrivateKeyManager} from './ecies_aead_hkdf_private_key_manager';

export function register() {
  Registry.registerKeyManager(new EciesAeadHkdfPrivateKeyManager());
}
