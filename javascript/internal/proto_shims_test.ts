/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as random from "../subtle/random";

import { PbKeyData } from "./proto";
import { bytesAsU8, bytesLength } from "./proto_shims";

describe("proto shims test", () => {
	it("transforms bytes to uint8array and returns byte length", () => {
		const rawKey = random.randBytes(32);

		const keyData = new PbKeyData()
			.setTypeUrl("key_type_url")
			.setValue(rawKey)
			.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

		expect(bytesAsU8(keyData.getValue())).toEqual(rawKey);
		expect(bytesLength(keyData.getValue())).toEqual(32);
	});
});
