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

import org.kohsuke.args4j.Option;

/**
 * Args for command to create an empty keyset.
 */
class CreateOptions extends OutOptions {
  @Option(name = "--google-cloud-kms-key-uri", required = false,
      usage = "The Google Cloud KMS master key to encrypt the keyset with")
  String gcpKmsMasterKeyValue;
  @Option(name = "--aws-kms-key-arn", required = false,
      usage = "The AWS KMS master key to encrypt the keyset with")
  String awsKmsMasterKeyValue;
}
