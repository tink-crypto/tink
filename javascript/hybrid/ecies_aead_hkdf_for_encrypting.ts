/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import EciesAeadHkdfPublicKeyManager from 'goog:tink.hybrid.EciesAeadHkdfPublicKeyManager'; // from //third_party/tink/javascript/hybrid:ecies_aead_hkdf_key_managers
import * as Registry from '../internal/registry';

export function register() {
  Registry.registerKeyManager(new EciesAeadHkdfPublicKeyManager());
}
