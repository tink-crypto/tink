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
 * Creates an empty keyset.
 */
public class CreateCommand extends CreateOptions implements Command {
  @Override
  public void run() throws Exception {
    create(outFilename, credentialFilename, gcpKmsMasterKeyValue, awsKmsMasterKeyValue);
  }

  /**
   * Creates an empty keyset and writes it to {@code outFilename}.
   * Attempts to encrypt the keyset using {@code credentialFilename} and either
   * {@code gcpKmsMasterKeyValue} or {@code awsKmsMasterKeyValue}.
   * @throws IllegalArgumentException if both {@code gcpKmsMasterKeyValue} and
   * {code awsKmsMasterKeyValue} are set.
   */
  public static void create(String outFilename, String credentialFilename,
      String gcpKmsMasterKeyValue, String awsKmsMasterKeyValue)
      throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}