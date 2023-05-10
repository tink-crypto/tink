/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {HmacKeyManager} from './hmac_key_manager';
import {MacWrapper} from './mac_wrapper';

/**
 * Methods and constants for registering all instances of Mac key types
 * supported in a particular release of Tink.
 *
 * To register all Mac key types from the current Tink release, one can do:
 *
 * import * as macConfig from './mac_config'
 * macConfig.register();
 *
 */
export function register() {
  HmacKeyManager.register();
  MacWrapper.register();
}

// Suppressing enforced comments since the names are self-explanatory.
// tslint:disable:enforce-comments-on-exported-symbols
export const MAC_PRIMITIVE_NAME = 'Mac';
export const HMAC_KEY_TYPE_URL = HmacKeyManager.KEY_TYPE;
