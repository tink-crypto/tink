// Copyright 2020 Google LLC
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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.TextFormat;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;

/** Helper functions to load testdata. */
public final class Testdata {

  private static String getTinkRootPath() throws FileNotFoundException {
    String srcDir = System.getenv().get("TEST_SRCDIR");
    if ((srcDir == null) || srcDir.isEmpty()) {
      throw new FileNotFoundException("TEST_SRCDIR not found");
    }
    String path = srcDir + "/google3/third_party/tink";
    if (new File(path).exists()) {
      return path;
    }
    String path2 = srcDir + "/tink_base";
    if (new File(path2).exists()) {
      return path2;
    }
    throw new FileNotFoundException("Tink root path not found");
  }

  public static String getTestdataPath() throws FileNotFoundException {
    return getTinkRootPath() + "/testdata";
  }

  public static KeyTemplate getKeyTemplateProto(
      String dirName, String templateName) throws IOException, GeneralSecurityException {
    File tmplFile = new File(getTestdataPath() + "/templates/" + dirName, templateName);
    KeyTemplate.Builder protoBuilder = KeyTemplate.newBuilder();
    TextFormat.merge(new InputStreamReader(new FileInputStream(tmplFile), UTF_8), protoBuilder);
    return protoBuilder.build();
  }

  private Testdata() {}
}
