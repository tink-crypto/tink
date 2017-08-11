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

package com.google.crypto.tink;

import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.Keyset;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class consists exclusively of static methods that create new readers that can reader
 * keysets in proto binary format from common storage systems.
 */
public final class KeysetReaders {
  public static KeysetReader withInputStream(InputStream stream) {
    return new InputStreamKeysetReader(stream);
  }

  public static KeysetReader withBytes(final byte[] bytes) {
    return new InputStreamKeysetReader(new ByteArrayInputStream(bytes));
  }

  public static KeysetReader withFile(File file) throws IOException {
    return new InputStreamKeysetReader(new FileInputStream(file));
  }

  private static class InputStreamKeysetReader implements KeysetReader {
    private final InputStream inputStream;

    public InputStreamKeysetReader(InputStream stream) {
      inputStream = stream;
    }

    @Override
    public Keyset read() throws IOException {
      return Keyset.parseFrom(inputStream);
    }

    @Override
    public EncryptedKeyset readEncrypted() throws IOException {
      return EncryptedKeyset.parseFrom(inputStream);
    }
  }
}
