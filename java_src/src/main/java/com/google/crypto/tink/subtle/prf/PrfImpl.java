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
package com.google.crypto.tink.subtle.prf;

import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/** Class that implements the Prf primitive by wrapping a StreamingPrf. */
@Immutable
public class PrfImpl implements Prf {
  private final StreamingPrf prfStreamer;

  private PrfImpl(StreamingPrf prfStreamer) {
    this.prfStreamer = prfStreamer;
  }

  /** Creates a Prf primitive from a StreamingPrf primitive. */
  public static PrfImpl wrap(StreamingPrf prfStreamer) {
    return new PrfImpl(prfStreamer);
  }

  /** Reads the specified number of bytes from the string or throws an exception. */
  private static byte[] readBytesFromStream(InputStream stream, int outputLength)
      throws GeneralSecurityException {
    try {
      byte[] output = new byte[outputLength];
      int offset = 0;
      while (offset < outputLength) {
        int bytesRead = stream.read(output, offset, outputLength - offset);
        if (bytesRead <= 0) {
          throw new GeneralSecurityException(
              "Provided StreamingPrf terminated before providing requested number of bytes.");
        }
        offset += bytesRead;
      }
      return output;
    } catch (IOException exception) {
      throw new GeneralSecurityException(exception);
    }
  }

  @Override
  public byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException {
    if (input == null) {
      throw new GeneralSecurityException("Invalid input provided.");
    }
    if (outputLength <= 0) {
      throw new GeneralSecurityException("Invalid outputLength specified.");
    }
    InputStream prfStream = prfStreamer.computePrf(input);
    return readBytesFromStream(prfStream, outputLength);
  }
}
