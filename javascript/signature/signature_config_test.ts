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

import { EcdsaPrivateKeyManager } from "./ecdsa_private_key_manager";
import { EcdsaPublicKeyManager } from "./ecdsa_public_key_manager";
import { PublicKeySign } from "./internal/public_key_sign";
import { PublicKeyVerify } from "./internal/public_key_verify";
import * as SignatureConfig from "./signature_config";
import { SignatureKeyTemplates } from "./signature_key_templates";

describe("signature config test", () => {
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
		expect(SignatureConfig.VERIFY_PRIMITIVE_NAME).toBe(
			VERIFY_PRIMITIVE_NAME
		);
		expect(SignatureConfig.SIGN_PRIMITIVE_NAME).toBe(SIGN_PRIMITIVE_NAME);

		expect(SignatureConfig.ECDSA_PUBLIC_KEY_TYPE).toBe(
			ECDSA_PUBLIC_KEY_TYPE
		);
		expect(SignatureConfig.ECDSA_PRIVATE_KEY_TYPE).toBe(
			ECDSA_PRIVATE_KEY_TYPE
		);
	});

	it("register, correct key managers were registered", () => {
		SignatureConfig.register();

		// Test that the corresponding key managers were registered.
		const publicKeyManager = Registry.getKeyManager(ECDSA_PUBLIC_KEY_TYPE);
		expect(publicKeyManager instanceof EcdsaPublicKeyManager).toBe(true);

		const privateKeyManager = Registry.getKeyManager(
			ECDSA_PRIVATE_KEY_TYPE
		);
		expect(privateKeyManager instanceof EcdsaPrivateKeyManager).toBe(true);
	});

	// Check that everything was registered correctly and thus new keys may be
	// generated using the predefined key templates and then they may be used for
	// encryption and decryption.
	it("register, predefined templates should work", async () => {
		SignatureConfig.register();
		let templates = [
			SignatureKeyTemplates.ecdsaP256(),
			SignatureKeyTemplates.ecdsaP256IeeeEncoding(),
			SignatureKeyTemplates.ecdsaP384(),
			SignatureKeyTemplates.ecdsaP384IeeeEncoding(),
			SignatureKeyTemplates.ecdsaP521(),
			SignatureKeyTemplates.ecdsaP521IeeeEncoding(),
		];
		for (const template of templates) {
			const privateKeyData = await Registry.newKeyData(template);
			const privateKeysetHandle =
				createKeysetHandleFromKeyData(privateKeyData);
			const publicKeySign =
				await privateKeysetHandle.getPrimitive<PublicKeySign>(
					PublicKeySign
				);
			const publicKeyData = Registry.getPublicKeyData(
				privateKeyData.getTypeUrl(),
				bytesAsU8(privateKeyData.getValue())
			);
			const publicKeysetHandle =
				createKeysetHandleFromKeyData(publicKeyData);
			const publicKeyVerify =
				await publicKeysetHandle.getPrimitive<PublicKeyVerify>(
					PublicKeyVerify
				);
			const data = Random.randBytes(10);
			const signature = await publicKeySign.sign(data);
			const isValid = await publicKeyVerify.verify(signature, data);

			expect(isValid).toBe(true);
		}
	});
});

// Constants used in tests.
const VERIFY_PRIMITIVE_NAME = "PublicKeyVerify";
const SIGN_PRIMITIVE_NAME = "PublicKeySign";
const ECDSA_PUBLIC_KEY_TYPE =
	"type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
const ECDSA_PRIVATE_KEY_TYPE =
	"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

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
