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
 * Changes the master key of a keyset. The keyset will be encrypted with the new master key.
 */
public class ChangeMasterKeyCommand extends ChangeMasterKeyOptions implements Command {
  @Override
  public void run() throws Exception {
    changeMasterKey(outFilename, inFilename, credentialFilename, newMasterKeyValue,
        newCredentialFilename);
  }

  /**
   * Reencrypts the keyset in {@code inFilename} using {@code newMasterKeyValue}, writes the
   * resulting keyset to {@code outFilename}.
   */
  public static void changeMasterKey(String outFilename, String inFilename,
      String credentialFilename, String newMasterKeyValue, String newCredentialFilename)
      throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}