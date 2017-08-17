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
import java.io.InputStream;
import org.kohsuke.args4j.Option;

/**
 * Common args for commands that read from file.
 */
class InOptions {
  @Option(
      name = "--in",
      handler = InputStreamHandler.class,
      required = false,
      usage = "The input filename to read the keyset from or standard input if not specified")
  InputStream inputStream;

  @Option(
      name = "--in-format",
      required = false,
      metaVar = "TEXT | BINARY",
      usage = "The input format: TEXT or BINARY (case-insensitive). TEXT is default")
  String inFormat;

  @Option(
      name = "--master-key-uri",
      required = false,
      usage = "The keyset might be encrypted with a master key in Google Cloud KMS or AWS KMS. "
          + "This option specifies the URI of the master key. "
          + "If missing, read or write cleartext keysets. "
          + "Google Cloud KMS keys have this format: "
          + "gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*. "
          + "AWS KMS keys have this format: "
          + "aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>."
  )
  String masterKeyUri;

  @Option(
      name = "--credential",
      required = false,
      usage =
          "If --masterKeyUri is specifies, this option specifies the credentials file path. "
          + "If missing, use default credentials. "
          + "Google Cloud credentials are service account JSON files. "
          + "AWS credentials are properties files with the AWS access key ID is expected "
          + "to be in the accessKey property and the AWS secret key is expected to be in "
          + "the secretKey property."
      )
  String credentialPath;

  void validate() {
    if (inputStream == null) {
      inputStream = System.in;
    }
    try {
      TinkeyUtil.validateInputOutputFormat(inFormat);
    } catch (Exception e) {
      SubtleUtil.die(e.toString());
    }
  }
}
