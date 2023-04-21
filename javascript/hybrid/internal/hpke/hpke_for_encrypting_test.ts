/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import * as registry from '../../../internal/registry';

import * as hpkeForEncrypting from './hpke_for_encrypting';
import {HpkePublicKeyManager} from './hpke_public_key_manager';


describe('hpke for encrypting test', () => {
  it('public key registers correctly', () => {
    registry.reset();
    // Confirm that it fails before registering.
    try {
      registry.getKeyManager(
          'type.googleapis.com/google.crypto.tink.HpkePublicKey');
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Key manager for key type ' +
              'type.googleapis.com/google.crypto.tink.HpkePublicKey' +
              ' has not been registered.');
    }

    hpkeForEncrypting.register();

    // Test that the corresponding key manager was registered.
    const hpkePublicKeyManager = registry.getKeyManager(
        'type.googleapis.com/google.crypto.tink.HpkePublicKey');
    expect(hpkePublicKeyManager instanceof HpkePublicKeyManager).toBe(true);
  });
});
