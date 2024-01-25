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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A {@link KeysetWriter} that can write to some source cleartext or encrypted keysets in <a
 * href="https://developers.google.com/protocol-buffers/docs/encoding">proto binary wire format</a>.
 *
 * @since 1.0.0
 */
public final class BinaryKeysetWriter implements KeysetWriter {
  private final OutputStream outputStream;

  private BinaryKeysetWriter(OutputStream stream) {
    this.outputStream = stream;
  }

  /**
   * Static method to create a BinaryKeysetWriter that writes to an {@link OutputStream}.
   *
   * <p>{@code stream} will be immmediately closed after the keyset is written.
   */
  public static KeysetWriter withOutputStream(OutputStream stream) {
    return new BinaryKeysetWriter(stream);
  }

  /**
   * Static method to create a BinaryKeysetWriter that writes to a file.
   *
   * @deprecated Inline the function.
   */
  @InlineMe(
      replacement = "BinaryKeysetWriter.withOutputStream(new FileOutputStream(file))",
      imports = {"com.google.crypto.tink.BinaryKeysetWriter", "java.io.FileOutputStream"})
  @Deprecated
  public static KeysetWriter withFile(File file) throws IOException {
    return withOutputStream(new FileOutputStream(file));
  }

  @Override
  public void write(Keyset keyset) throws IOException {
    try {
      keyset.writeTo(outputStream);
    } finally {
      outputStream.close();
    }
  }

  @Override
  public void write(EncryptedKeyset keyset) throws IOException {
    try {
      keyset.toBuilder().clearKeysetInfo().build().writeTo(outputStream);
    } finally {
      outputStream.close();
    }
  }
}
