// Copyright 2017 Google Inc.
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

package com.google.cloud.crypto.tink.tinkey;

/**
 * Creates a public keyset from an existing keyset.
 */
public class CreatePublicKeysetCommand extends InOptions implements Command {
  @Override
  public void run() throws Exception {
    createPublicKeyset(outFilename, inFilename, credentialFilename);
  }

  /**
   * Extracts public keys from {@code inFilename} (using {@code credentialFilename} to decrypt
   * if it is encrypted) and writes public keys to {@code outFilename}.
   */
  public static void createPublicKeyset(String outFilename, String inFilename,
      String credentialFilename) throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}