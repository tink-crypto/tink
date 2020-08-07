/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * The base class for all security exceptions.
 */
export class SecurityException extends Error {
  constructor(message?: string) {
    super(message);
    Object.setPrototypeOf(this, SecurityException.prototype);
  }
}
SecurityException.prototype.name = 'SecurityException';
