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

import com.google.crypto.tink.subtle.Validators;
import java.io.File;
import java.io.IOException;
import org.kohsuke.args4j.Option;

/**
 * Options for convert-keyset command.
 */
class ConvertKeysetOptions extends OutOptions {
  @Option(name = "--new-master-key-uri", required = false,
      usage = "The new master key URI")
  String newMasterKeyUri;

  @Option(name = "--new-credential", required = false,
      usage = "The new master key credential, must exist if specified")
  String newCredentialPath;

  @Override
  void validate() throws IOException {
    super.validate();
    if (newCredentialPath != null) {
      Validators.validateExists(new File(newCredentialPath));
    }
  }
}
