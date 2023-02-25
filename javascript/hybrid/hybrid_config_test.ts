/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { KeysetHandle } from "../internal/keyset_handle";
import {
	PbKeyData,
	PbKeyset,
	PbKeysetKey,
	PbKeyStatusType,
	PbOutputPrefixType,
} from "../internal/proto";
import { bytesAsU8 } from "../internal/proto_shims";
import * as Registry from "../internal/registry";
import * as Random from "../subtle/random";

import { EciesAeadHkdfPrivateKeyManager } from "./ecies_aead_hkdf_private_key_manager";
import { EciesAeadHkdfPublicKeyManager } from "./ecies_aead_hkdf_public_key_manager";
import * as HybridConfig from "./hybrid_config";
import { HybridKeyTemplates } from "./hybrid_key_templates";
import { HybridDecrypt } from "./internal/hybrid_decrypt";
import { HybridEncrypt } from "./internal/hybrid_encrypt";

describe("hybrid config test", () => {
	beforeEach(() => {
		// Use a generous promise timeout for running continuously.
		jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000; // 1000s
	});

	afterEach(() => {
		Registry.reset();
		// Reset the promise timeout to default value.
		jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000; // 1s
	});

	it("constants", () => {
		expect(HybridConfig.ENCRYPT_PRIMITIVE_NAME).toBe(
			ENCRYPT_PRIMITIVE_NAME
		);
		expect(HybridConfig.DECRYPT_PRIMITIVE_NAME).toBe(
			DECRYPT_PRIMITIVE_NAME
		);

		expect(HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE).toBe(
			ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE
		);
		expect(HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE).toBe(
			ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE
		);
	});

	it("register, correct key managers were registered", () => {
		HybridConfig.register();

		// Test that the corresponding key managers were registered.
		const publicKeyManager = Registry.getKeyManager(
			ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE
		);
		expect(publicKeyManager instanceof EciesAeadHkdfPublicKeyManager).toBe(
			true
		);

		const privateKeyManager = Registry.getKeyManager(
			ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE
		);
		expect(
			privateKeyManager instanceof EciesAeadHkdfPrivateKeyManager
		).toBe(true);
	});

	// Check that everything was registered correctly and thus new keys may be
	// generated using the predefined key templates and then they may be used for
	// encryption and decryption.
	it("register, predefined templates should work", async () => {
		HybridConfig.register();
		let templates = [
			HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm(),
			HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256(),
		];
		for (const template of templates) {
			const privateKeyData = await Registry.newKeyData(template);
			const privateKeysetHandle =
				createKeysetHandleFromKeyData(privateKeyData);
			const hybridDecrypt =
				await privateKeysetHandle.getPrimitive<HybridDecrypt>(
					HybridDecrypt
				);

			const publicKeyData = Registry.getPublicKeyData(
				privateKeyData.getTypeUrl(),
				bytesAsU8(privateKeyData.getValue())
			);
			const publicKeysetHandle =
				createKeysetHandleFromKeyData(publicKeyData);
			const hybridEncrypt =
				await publicKeysetHandle.getPrimitive<HybridEncrypt>(
					HybridEncrypt
				);

			const plaintext = new Uint8Array(Random.randBytes(10));
			const contextInfo = new Uint8Array(Random.randBytes(8));
			const ciphertext = await hybridEncrypt.encrypt(
				plaintext,
				contextInfo
			);
			const decryptedCiphertext = await hybridDecrypt.decrypt(
				ciphertext,
				contextInfo
			);

			expect(decryptedCiphertext).toEqual(plaintext);
		}
	});
});

// Constants used in tests.
const ENCRYPT_PRIMITIVE_NAME = "HybridEncrypt";
const DECRYPT_PRIMITIVE_NAME = "HybridDecrypt";
const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE =
	"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE =
	"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

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

	const keyset = new PbKeyset();
	keyset.addKey(key);
	keyset.setPrimaryKeyId(keyId);
	return new KeysetHandle(keyset);
}
