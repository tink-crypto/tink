/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * Exception used when a function receives an invalid argument.
 */
export class InvalidArgumentsException extends Error {
  constructor(message?: string) {
    super(message);
    Object.setPrototypeOf(this, InvalidArgumentsException.prototype);
  }
}
InvalidArgumentsException.prototype.name = 'InvalidArgumentsException';
