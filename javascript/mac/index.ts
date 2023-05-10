/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

export * from './mac';
import * as hmac from './hmac';
import {MacWrapper} from './mac_wrapper';

export {hmacSha256Tag128KeyTemplate, hmacSha256Tag256KeyTemplate, hmacSha512Tag256KeyTemplate, hmacSha512Tag512KeyTemplate} from './hmac';

/** Registers wrappers and mac key managers */
export function register() {
  hmac.register();
  MacWrapper.register();
}
