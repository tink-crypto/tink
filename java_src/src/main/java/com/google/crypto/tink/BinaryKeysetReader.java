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
import com.google.errorprone.annotations.InlineMe;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A {@link KeysetReader} that can read from some source cleartext or encrypted keysets in <a
 * href="https://developers.google.com/protocol-buffers/docs/encoding">proto binary wire format</a>.
 *
 * @since 1.0.0
 */
public final class BinaryKeysetReader implements KeysetReader {
  private final InputStream inputStream;

  /**
   * Static method to create a BinaryKeysetReader from an {@link InputStream}.
   *
   * <p>Note: the input stream won't be read until {@link BinaryKeysetReader#read} or {@link
   * BinaryKeysetReader#readEncrypted} is called, and will be closed immediately after the keyset is
   * read.
   */
  public static KeysetReader withInputStream(InputStream stream) {
    return new BinaryKeysetReader(stream);
  }

  /** Static method to create a BinaryKeysetReader from a byte arrary. */
  public static KeysetReader withBytes(final byte[] bytes) {
    return new BinaryKeysetReader(new ByteArrayInputStream(bytes));
  }

  /**
   * Static method to create a BinaryKeysetReader from a file.
   *
   * <p>Note: the input file won't be read until {@link BinaryKeysetReader#read} or {@link
   * BinaryKeysetReader#readEncrypted} is called.
   */
  @InlineMe(
      replacement = "BinaryKeysetReader.withInputStream(new FileInputStream(file))",
      imports = {"com.google.crypto.tink.BinaryKeysetReader", "java.io.FileInputStream"})
  @Deprecated
  public static KeysetReader withFile(File file) throws IOException {
    return withInputStream(new FileInputStream(file));
  }

  private BinaryKeysetReader(InputStream stream) {
    this.inputStream = stream;
  }

  @Override
  public Keyset read() throws IOException {
    try {
      return Keyset.parseFrom(inputStream, ExtensionRegistryLite.getEmptyRegistry());
    } finally {
      inputStream.close();
    }
  }

  @Override
  public EncryptedKeyset readEncrypted() throws IOException {
    try {
      return EncryptedKeyset.parseFrom(inputStream, ExtensionRegistryLite.getEmptyRegistry());
    } finally {
      inputStream.close();
    }
  }
}
