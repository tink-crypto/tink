/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
	assertMessageEquals,
	createKeyset,
} from "../testing/internal/test_utils";

import { BinaryKeysetReader } from "./binary_keyset_reader";
import { BinaryKeysetWriter } from "./binary_keyset_writer";

describe("binary keyset writer test", () => {
	it("get serialized key set", () => {
		const dummyKeyset = createKeyset();

		// Write the keyset.
		const writer = new BinaryKeysetWriter();
		const serializedKeyset = writer.encodeBinary(dummyKeyset);

		// Read the keyset proto serialization.
		const reader = BinaryKeysetReader.withUint8Array(serializedKeyset);
		const keysetFromReader = reader.read();

		// Test that it returns the same object as was created.
		assertMessageEquals(keysetFromReader, dummyKeyset);
	});
});
