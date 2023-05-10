/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {KeysetHandle} from '../internal/keyset_handle';
import {PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as registry from '../internal/registry';
import * as random from '../subtle/random';

import {HmacKeyManager} from './hmac_key_manager';
import {Mac} from './internal/mac';
import * as macConfig from './mac_config';
import * as macKeyTemplates from './mac_key_templates';

// Constant used in tests.
const HMAC_KEY_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HmacKey';

describe('mac config test', () => {
  beforeEach(() => {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(() => {
    registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('check constants', () => {
    expect(macConfig.MAC_PRIMITIVE_NAME).toBe('Mac');
    expect(macConfig.HMAC_KEY_TYPE_URL).toBe(HMAC_KEY_TYPE_URL);
  });

  it('register, corresponding key managers were registered', () => {
    macConfig.register();

    // Test that the hmac key manager was registered.
    const hmacKeyManager = registry.getKeyManager(HMAC_KEY_TYPE_URL);
    expect(hmacKeyManager instanceof HmacKeyManager).toBe(true);
  });

  // Check that everything was registered correctly and thus new keys may be
  // generated using the predefined key templates and then they may be used for
  // computing and verifying the mac.
  it('register, predefined templates should work', async () => {
    macConfig.register();
    const templates = [
      macKeyTemplates.hmacSha256Tag128(), macKeyTemplates.hmacSha256Tag256(),
      macKeyTemplates.hmacSha512Tag256(), macKeyTemplates.hmacSha512Tag512()
    ];
    for (const template of templates) {
      const keyData = await registry.newKeyData(template);
      const keysetHandle = createKeysetHandleFromKeyData(keyData);
      const mac = await keysetHandle.getPrimitive<Mac>(Mac);
      const data = random.randBytes(10);

      const tag = await mac.computeMac(data);
      const isValid = await mac.verifyMac(tag, data);

      expect(isValid).toBe(true);
    }
  });
});

/**
 * Creates a keyset containing only the key given by keyData and returns it
 * wrapped in a KeysetHandle.
 */
function createKeysetHandleFromKeyData(keyData: PbKeyData): KeysetHandle {
  const keyId = 1;
  const key = new PbKeysetKey()
                  .setKeyData(keyData)
                  .setStatus(PbKeyStatusType.ENABLED)
                  .setKeyId(keyId)
                  .setOutputPrefixType(PbOutputPrefixType.TINK);

  const keyset = new PbKeyset().addKey(key).setPrimaryKeyId(keyId);
  return new KeysetHandle(keyset);
}
