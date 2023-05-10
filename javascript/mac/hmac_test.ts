/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as registry from '../internal/registry';

import * as hmac from './hmac';
import {HmacKeyManager} from './hmac_key_manager';


describe('hmac test', () => {
  it('hmac key registers correctly', () => {
    registry.reset();
    // Confirm that it fails before registering.
    expect(() => {
      registry.getKeyManager('type.googleapis.com/google.crypto.tink.HmacKey');
    })
        .toThrowError(
            SecurityException,
            'Key manager for key type ' +
                'type.googleapis.com/google.crypto.tink.HmacKey' +
                ' has not been registered.');

    hmac.register();

    // Test that the corresponding key manager was registered.
    const hmacKeyManager = registry.getKeyManager(
        'type.googleapis.com/google.crypto.tink.HmacKey');
    expect(hmacKeyManager instanceof HmacKeyManager).toBe(true);
  });
});
