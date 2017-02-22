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

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;

/**
 * Args for {@code EnvelopeCommand}.
 */
class EnvelopeOptions {
  @Option(name = "--out", required = true,
      usage = "The output filename to write the keyset to")
  String outFilename;
  @Option(name = "--dek-type", required = true,
      usage = "The key type of the DEK")
  String dekTypeValue;
  @Option(name = "--dek-format", required = true,
      usage = "The key format of the DEK")
  String dekFormatValue;
  @Option(name = "--google-cloud-kms-key-uri", required = true,
      usage = "The URI of CryptoKey in Google Cloud KMS")
  String kmsKeyUriValue;
}
