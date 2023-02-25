/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { InvalidArgumentsException } from "../../../exception/invalid_arguments_exception";
import * as bytes from "../../../subtle/bytes";
import * as ellipticCurves from "../../../subtle/elliptic_curves";
import { randBytes } from "../../../subtle/random";

import {
	fromBytes,
	fromCryptoKeyPair,
} from "./nist_curves_hpke_kem_private_key";

interface TestVector {
	name: string;
	curveType: ellipticCurves.CurveType.P256 | ellipticCurves.CurveType.P521;
	senderPublicKey: Uint8Array;
	senderPrivateKey: Uint8Array;
}

/**
 * Test vectors as described in @see https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
 */
const TEST_VECTORS: TestVector[] = [
	/** Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
	{
		name: "DHKEM(P-521, HKDF-SHA512)",
		curveType: ellipticCurves.CurveType.P256,
		senderPublicKey: bytes.fromHex(
			"04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
		),
		senderPrivateKey: bytes.fromHex(
			"4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"
		),
	},
	/** Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
	{
		name: "DHKEM(P-521, HKDF-SHA512)",
		curveType: ellipticCurves.CurveType.P521,
		senderPublicKey: bytes.fromHex(
			"040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
		),
		senderPrivateKey: bytes.fromHex(
			"014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b"
		),
	},
];

describe("NistCurvesHpkeKemPrivateKey", () => {
	for (const testInfo of TEST_VECTORS) {
		it("should instantiate from key raw bytes and serialize public key correctly", async () => {
			const privateKey = await fromBytes({
				privateKey: testInfo.senderPrivateKey,
				publicKey: testInfo.senderPublicKey,
				curveType: testInfo.curveType,
			});
			const serialiazedPublicKey =
				await privateKey.getSerializedPublicKey();
			expect(serialiazedPublicKey).toEqual(testInfo.senderPublicKey);
		});

		describe("fails to instantiate from invalid", () => {
			it("private key", async () => {
				await expectAsync(
					fromBytes({
						privateKey: new Uint8Array(0),
						publicKey: testInfo.senderPublicKey,
						curveType: testInfo.curveType,
					})
				).toBeRejectedWithError(DOMException);
			});

			it("public key raw bytes", async () => {
				await expectAsync(
					fromBytes({
						privateKey: testInfo.senderPrivateKey,
						publicKey: randBytes(testInfo.senderPublicKey.length),
						curveType: testInfo.curveType,
					})
				).toBeRejectedWithError(InvalidArgumentsException);
			});

			it("ECDH curve type", async () => {
				const mismatchedCurveType =
					testInfo.curveType === ellipticCurves.CurveType.P256
						? ellipticCurves.CurveType.P521
						: ellipticCurves.CurveType.P256;

				await expectAsync(
					fromBytes({
						privateKey: testInfo.senderPrivateKey,
						publicKey: testInfo.senderPublicKey,
						curveType: mismatchedCurveType,
					})
				).toBeRejectedWithError(InvalidArgumentsException);
			});

			it("algorithm in the CryptoKeyPair", async () => {
				const invalidKeyPair: CryptoKeyPair =
					await ellipticCurves.generateKeyPair(
						"ECDSA",
						ellipticCurves.curveToString(testInfo.curveType)
					);
				await expectAsync(
					fromCryptoKeyPair(invalidKeyPair)
				).toBeRejectedWithError(InvalidArgumentsException);
			});

			it("key type on the private key in a CryptoKeyPair", async () => {
				const keyPair: CryptoKeyPair =
					await ellipticCurves.generateKeyPair(
						"ECDH",
						ellipticCurves.curveToString(testInfo.curveType)
					);
				keyPair.privateKey = keyPair.publicKey;
				await expectAsync(
					fromCryptoKeyPair(keyPair)
				).toBeRejectedWithError(InvalidArgumentsException);
			});

			it("key type on the public key in a CryptoKeyPair", async () => {
				const keyPair: CryptoKeyPair =
					await ellipticCurves.generateKeyPair(
						"ECDH",
						ellipticCurves.curveToString(testInfo.curveType)
					);
				keyPair.publicKey = keyPair.privateKey;
				await expectAsync(
					fromCryptoKeyPair(keyPair)
				).toBeRejectedWithError(InvalidArgumentsException);
			});
		});
	}
});
