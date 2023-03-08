/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { PbKeyset } from "./proto";

describe("proto test", () => {
	it("field", () => {
		const keyset = new PbKeyset().setPrimaryKeyId(1);
		expect(keyset.getPrimaryKeyId()).toBe(1);
	});
});
