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

package com.google.crypto.tink.tinkey;

import com.google.crypto.tink.subtle.SubtleUtil;
import java.io.File;
import java.io.IOException;
import org.kohsuke.args4j.Option;

/**
 * Options for change-master-key command.
 */
class ChangeMasterKeyOptions extends InOptions {
  @Option(name = "--new-master-key", required = true,
      usage = "The new master key to encrypt the keyset with")
  String newMasterKeyValue;

  @Option(name = "--new-credential", required = false,
      usage = "The filename containing a credential of the master key")
  File newCredentialFile;

  @Override
  void validate() {
    super.validate();
    if (newCredentialFile != null) {
      try {
        SubtleUtil.validateExists(newCredentialFile);
      } catch (IOException e) {
        SubtleUtil.die(e.toString());
      }
    }
  }
}
