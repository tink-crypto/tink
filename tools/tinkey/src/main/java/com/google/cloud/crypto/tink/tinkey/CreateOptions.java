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

import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import org.kohsuke.args4j.Option;

/**
 * Args for command to create a keyset.
 */
class CreateOptions extends OutOptions {
  @Option(
      name = "--key-template",
      handler = KeyTemplateHandler.class,
      metaVar = "aes-128-gcm.proto",
      required = true,
      usage =
          "The input filename to read the key template from. "
          + "Pre-generated templates can be found at "
          + "https://github.com/google/tink/tree/master/tools/tinkey/keytemplates."
  )
  KeyTemplate keyTemplate;

  @Option(name = "--gcp-kms-key-uri",
      required = false,
      usage = "The Google Cloud KMS master key to encrypt the keyset with.")
  String gcpKmsMasterKeyUriValue;

  @Option(name = "--aws-kms-key-arn",
      required = false,
      usage = "The AWS KMS master key to encrypt the keyset with.")
  String awsKmsMasterKeyUriValue;

  @Override
  void validate() {
    super.validate();
    try {
      if (gcpKmsMasterKeyUriValue != null && awsKmsMasterKeyUriValue != null) {
        SubtleUtil.die("Cannot set both --gcp-kms-key-uri and --aws-kms-key-arn");
      }
      if (gcpKmsMasterKeyUriValue != null) {
        SubtleUtil.validateCloudKmsCryptoKeyUri(gcpKmsMasterKeyUriValue);
      }
    } catch (Exception e) {
      SubtleUtil.die(e.toString());
    }
  }
}
