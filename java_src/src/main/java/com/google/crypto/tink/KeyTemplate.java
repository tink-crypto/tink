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

package com.google.crypto.tink;

import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;

/** A KeyTemplate specifies how to generate keys of a particular type. */
@Immutable
public final class KeyTemplate {
  private final com.google.crypto.tink.proto.KeyTemplate kt;

  /**
   * Tink produces and accepts ciphertexts or signatures that consist of a prefix and a payload. The
   * payload and its format is determined entirely by the primitive, but the prefix has to be one of
   * the following 4 types:
   *
   * <ul>
   *   <li>Legacy: prefix is 5 bytes, starts with \x00 and followed by a 4-byte key id that is
   *       computed from the key material.
   *   <li>Crunchy: prefix is 5 bytes, starts with \x00 and followed by a 4-byte key id that is
   *       generated randomly.
   *   <li>Tink : prefix is 5 bytes, starts with \x01 and followed by 4-byte key id that is
   *       generated randomly.
   *   <li>Raw : prefix is 0 byte, i.e., empty.
   * </ul>
   */
  public enum OutputPrefixType {
    TINK,
    LEGACY,
    RAW,
    CRUNCHY
  }

  static OutputPrefixType fromProto(
      com.google.crypto.tink.proto.OutputPrefixType outputPrefixType) {
    switch (outputPrefixType) {
      case TINK:
        return OutputPrefixType.TINK;
      case LEGACY:
        return OutputPrefixType.LEGACY;
      case RAW:
        return OutputPrefixType.RAW;
      case CRUNCHY:
        return OutputPrefixType.CRUNCHY;
      default:
        throw new IllegalArgumentException("Unknown output prefix type");
    }
  }

  static com.google.crypto.tink.proto.OutputPrefixType toProto(OutputPrefixType outputPrefixType) {
    switch (outputPrefixType) {
      case TINK:
        return com.google.crypto.tink.proto.OutputPrefixType.TINK;
      case LEGACY:
        return com.google.crypto.tink.proto.OutputPrefixType.LEGACY;
      case RAW:
        return com.google.crypto.tink.proto.OutputPrefixType.RAW;
      case CRUNCHY:
        return com.google.crypto.tink.proto.OutputPrefixType.CRUNCHY;
    }
    throw new IllegalArgumentException("Unknown output prefix type");
  }

  public static KeyTemplate create(
      String typeUrl, byte[] value, OutputPrefixType outputPrefixType) {
    return new KeyTemplate(
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setValue(ByteString.copyFrom(value))
            .setOutputPrefixType(toProto(outputPrefixType))
            .build());
  }

  private KeyTemplate(com.google.crypto.tink.proto.KeyTemplate kt) {
    this.kt = kt;
  }

  com.google.crypto.tink.proto.KeyTemplate getProto() {
    return kt;
  }

  public String getTypeUrl() {
    return kt.getTypeUrl();
  }

  public byte[] getValue() {
    return kt.getValue().toByteArray();
  }

  public OutputPrefixType getOutputPrefixType() {
    return fromProto(kt.getOutputPrefixType());
  }

  public Parameters toParameters() throws GeneralSecurityException {
    return TinkProtoParametersFormat.parse(kt.toByteArray());
  }
}
