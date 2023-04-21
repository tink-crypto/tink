/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import * as registry from '../../../internal/registry';

import * as hpkeForDecrypting from './hpke_for_decrypting';
import {HpkePrivateKeyManager} from './hpke_private_key_manager';


describe('hpke for decrypting test', () => {
  it('private key registers correctly', () => {
    registry.reset();
    // Confirm that it fails before registering.
    try {
      registry.getKeyManager(
          'type.googleapis.com/google.crypto.tink.HpkePrivateKey');
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Key manager for key type ' +
              'type.googleapis.com/google.crypto.tink.HpkePrivateKey' +
              ' has not been registered.');
    }

    hpkeForDecrypting.register();

    // Test that the corresponding key manager was registered.
    const hpkePrivateKeyManager = registry.getKeyManager(
        'type.googleapis.com/google.crypto.tink.HpkePrivateKey');
    expect(hpkePrivateKeyManager instanceof HpkePrivateKeyManager).toBe(true);
  });
});
