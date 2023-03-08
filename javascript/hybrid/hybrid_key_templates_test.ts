/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { AeadKeyTemplates } from "../aead/aead_key_templates";
import {
	PbEciesAeadHkdfKeyFormat,
	PbEllipticCurveType,
	PbHashType,
	PbOutputPrefixType,
	PbPointFormat,
} from "../internal/proto";
import { bytesAsU8 } from "../internal/proto_shims";
import { assertMessageEquals } from "../testing/internal/test_utils";

import { EciesAeadHkdfPrivateKeyManager } from "./ecies_aead_hkdf_private_key_manager";
import { HybridKeyTemplates } from "./hybrid_key_templates";

describe("hybrid key templates test", () => {
	it("ecies p256 hkdf hmac sha256 aes128 gcm", () => {
		// Expects function to create a key with following parameters.
		const expectedCurve = PbEllipticCurveType.NIST_P256;
		const expectedHkdfHashFunction = PbHashType.SHA256;
		const expectedAeadTemplate = AeadKeyTemplates.aes128Gcm();
		const expectedPointFormat = PbPointFormat.UNCOMPRESSED;
		const expectedOutputPrefix = PbOutputPrefixType.TINK;

		// Expected type URL is the one supported by EciesAeadHkdfPrivateKeyManager.
		const manager = new EciesAeadHkdfPrivateKeyManager();
		const expectedTypeUrl = manager.getKeyType();

		const keyTemplate =
			HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm();

		expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
		expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

		// Test values in key format.
		const keyFormat = PbEciesAeadHkdfKeyFormat.deserializeBinary(
			keyTemplate.getValue()
		);
		const params = keyFormat.getParams();
		expect(params!.getEcPointFormat()).toBe(expectedPointFormat);

		// Test KEM params.
		const kemParams = params!.getKemParams();
		expect(kemParams!.getCurveType()).toBe(expectedCurve);
		expect(kemParams!.getHkdfHashType()).toBe(expectedHkdfHashFunction);

		// Test DEM params.
		const demParams = params!.getDemParams();
		assertMessageEquals(demParams!.getAeadDem()!, expectedAeadTemplate);

		// Test that the template works with EciesAeadHkdfPrivateKeyManager.
		manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
	});

	it("ecies p256 hkdf hmac sha256 aes128 ctr hmac sha256", () => {
		// Expects function to create a key with following parameters.
		const expectedCurve = PbEllipticCurveType.NIST_P256;
		const expectedHkdfHashFunction = PbHashType.SHA256;
		const expectedAeadTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
		const expectedPointFormat = PbPointFormat.UNCOMPRESSED;
		const expectedOutputPrefix = PbOutputPrefixType.TINK;

		// Expected type URL is the one supported by EciesAeadHkdfPrivateKeyManager.
		const manager = new EciesAeadHkdfPrivateKeyManager();
		const expectedTypeUrl = manager.getKeyType();

		const keyTemplate =
			HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256();

		expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
		expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

		// Test values in key format.
		const keyFormat = PbEciesAeadHkdfKeyFormat.deserializeBinary(
			keyTemplate.getValue()
		);
		const params = keyFormat.getParams();
		expect(params!.getEcPointFormat()).toBe(expectedPointFormat);

		// Test KEM params.
		const kemParams = params!.getKemParams();
		expect(kemParams!.getCurveType()).toBe(expectedCurve);
		expect(kemParams!.getHkdfHashType()).toBe(expectedHkdfHashFunction);

		// Test DEM params.
		const demParams = params!.getDemParams();
		assertMessageEquals(demParams!.getAeadDem()!, expectedAeadTemplate);

		// Test that the template works with EciesAeadHkdfPrivateKeyManager.
		manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
	});
});
