/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
	PbAesCtrHmacAeadKeyFormat,
	PbHashType,
	PbOutputPrefixType,
} from "../internal/proto";
import { bytesAsU8 } from "../internal/proto_shims";

import { AesCtrHmacAeadKeyManager } from "./aes_ctr_hmac_aead_key_manager";
import { AesCtrHmacAeadKeyTemplates } from "./aes_ctr_hmac_aead_key_templates";

describe("aes ctr hmac aead key templates test", () => {
	it("aes128 ctr hmac sha256", () => {
		// Expects function to create key with following parameters.
		const expectedAesKeySize = 16;
		const expectedIvSize = 16;
		const expectedHmacKeySize = 32;
		const expectedTagSize = 16;
		const expectedHashFunction = PbHashType.SHA256;
		const expectedOutputPrefix = PbOutputPrefixType.TINK;

		// Expected type URL is the one supported by AesCtrHmacAeadKeyManager.
		const manager = new AesCtrHmacAeadKeyManager();
		const expectedTypeUrl = manager.getKeyType();

		const keyTemplate = AesCtrHmacAeadKeyTemplates.aes128CtrHmacSha256();

		expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
		expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

		// Test values in key format.
		const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
			keyTemplate.getValue()
		);

		// Test AesCtrKeyFormat.
		const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
		expect(aesCtrKeyFormat!.getKeySize()).toBe(expectedAesKeySize);
		expect(aesCtrKeyFormat!.getParams()!.getIvSize()).toBe(expectedIvSize);

		// Test HmacKeyFormat.
		const hmacKeyFormat = keyFormat.getHmacKeyFormat();
		expect(hmacKeyFormat!.getKeySize()).toBe(expectedHmacKeySize);
		expect(hmacKeyFormat!.getParams()!.getTagSize()).toBe(expectedTagSize);
		expect(hmacKeyFormat!.getParams()!.getHash()).toBe(
			expectedHashFunction
		);

		// Test that the template works with AesCtrHmacAeadKeyManager.
		manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
	});

	it("aes256 ctr hmac sha256", () => {
		// Expects function to create key with following parameters.
		const expectedAesKeySize = 32;
		const expectedIvSize = 16;
		const expectedHmacKeySize = 32;
		const expectedTagSize = 32;
		const expectedHashFunction = PbHashType.SHA256;
		const expectedOutputPrefix = PbOutputPrefixType.TINK;

		// Expected type URL is the one supported by AesCtrHmacAeadKeyManager.
		const manager = new AesCtrHmacAeadKeyManager();
		const expectedTypeUrl = manager.getKeyType();

		const keyTemplate = AesCtrHmacAeadKeyTemplates.aes256CtrHmacSha256();

		expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
		expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

		// Test values in key format.
		const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
			keyTemplate.getValue()
		);

		// Test AesCtrKeyFormat.
		const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
		expect(aesCtrKeyFormat!.getKeySize()).toBe(expectedAesKeySize);
		expect(aesCtrKeyFormat!.getParams()!.getIvSize()).toBe(expectedIvSize);

		// Test HmacKeyFormat.
		const hmacKeyFormat = keyFormat.getHmacKeyFormat();
		expect(hmacKeyFormat!.getKeySize()).toBe(expectedHmacKeySize);
		expect(hmacKeyFormat!.getParams()!.getTagSize()).toBe(expectedTagSize);
		expect(hmacKeyFormat!.getParams()!.getHash()).toBe(
			expectedHashFunction
		);

		// Test that the template works with AesCtrHmacAeadKeyManager.
		manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
	});
});
