// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkConfig;

/**
 * A command-line utility which tries to compare two keysets. If the keysets are different, the
 * utility is guaranteed to return false (it exists with an exception). If the keysets are the same,
 * but their serialization differs, it might still return throw an exception. These cases should be
 * rare, however (it should only be possible if a Key itself contains another KeyTemplate or a
 * KeyData with different serialization).
 */
public class CompareKeysetsCli {

  public static void main(String[] args) throws Exception {
    TinkConfig.register();
    if (args.length != 2) {
      System.out.println("Usage: CompareKeysetsCli keyset-file1 keyset-file2");
      System.exit(1);
    }
    System.out.println("Reading first keyset...");
    KeysetHandle keyset1 = CliUtil.readKeyset(args[0]);
    System.out.println("Reading second keyset...");
    KeysetHandle keyset2 = CliUtil.readKeyset(args[1]);
    CompareKeysets.compareKeysets(
        CleartextKeysetHandle.getKeyset(keyset1), CleartextKeysetHandle.getKeyset(keyset2));
  }

  private CompareKeysetsCli() {}
}
