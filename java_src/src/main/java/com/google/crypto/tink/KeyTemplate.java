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

import com.google.crypto.tink.internal.LegacyProtoParameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.TinkBugException;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** A KeyTemplate specifies how to generate keys of a particular type. */
@Immutable
public final class KeyTemplate {
  // Exactly one of kt and parameters is non-null.
  @Nullable private final com.google.crypto.tink.proto.KeyTemplate kt;

  @Nullable private final Parameters parameters;

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

  /**
   * @deprecated Use createFrom
   */
  @Deprecated
  public static KeyTemplate create(
      String typeUrl, byte[] value, OutputPrefixType outputPrefixType) {
    return new KeyTemplate(
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setValue(ByteString.copyFrom(value))
            .setOutputPrefixType(toProto(outputPrefixType))
            .build());
  }

  public static KeyTemplate createFrom(Parameters p) throws GeneralSecurityException {
    return new KeyTemplate(p);
  }

  private KeyTemplate(com.google.crypto.tink.proto.KeyTemplate kt) {
    this.kt = kt;
    this.parameters = null;
  }

  private KeyTemplate(Parameters parameters) {
    this.kt = null;
    this.parameters = parameters;
  }

  com.google.crypto.tink.proto.KeyTemplate getProto() {
    try {
      return getProtoMaybeThrow();
    } catch (GeneralSecurityException e) {
      // This may not really be a bug in Tink. This happens if a user uses a KeyTemplate
      // which was initialized with a parameter, but then calls one of the deprecated functions
      // below (getTypeUrl, etc.). I hope nobody does this -- but if they do, we recommend migrating
      // away from these functions. If they cannot, they need to register the corresponding
      // keymanager.
      throw new TinkBugException(
          "Parsing parameters failed in getProto(). You probably want to call some Tink register"
              + " function for "
              + parameters,
          e);
    }
  }

  com.google.crypto.tink.proto.KeyTemplate getProtoMaybeThrow() throws GeneralSecurityException {
    if (kt != null) {
      return kt;
    }
    if (parameters instanceof LegacyProtoParameters) {
      return ((LegacyProtoParameters) parameters).getSerialization().getKeyTemplate();
    }
    ProtoParametersSerialization s =
        MutableSerializationRegistry.globalInstance()
            .serializeParameters(parameters, ProtoParametersSerialization.class);
    return s.getKeyTemplate();
  }

  /**
   * @deprecated Instead, operate on the {@link Parameters} object obtained with {@link
   *     #toParameters}. If you really need this array, you need to first use
   *     TinkProtoParametersFormat to serialize this parameters object, then parse the result with
   *     the Tink-internal proto class "KeyTemplate".
   */
  @Deprecated
  public String getTypeUrl() {
    return getProto().getTypeUrl();
  }

  /**
   * @deprecated Instead, operate on the {@link Parameters} object obtained with {@link
   *     #toParameters}. If you really need this array, you need to first use
   *     TinkProtoParametersFormat to serialize this parameters object, then parse the result with
   *     the Tink-internal proto class "KeyTemplate".
   */
  @Deprecated
  public byte[] getValue() {
    return getProto().getValue().toByteArray();
  }

  /**
   * @deprecated Instead, operate on the {@link Parameters} object obtained with {@link
   *     #toParameters}. If you really need this value, you need to first use
   *     TinkProtoParametersFormat to serialize this parameters object, then parse the result with
   *     the Tink-internal proto class "KeyTemplate".
   */
  @Deprecated
  public OutputPrefixType getOutputPrefixType() {
    return fromProto(getProto().getOutputPrefixType());
  }

  public Parameters toParameters() throws GeneralSecurityException {
    if (parameters != null) {
      return parameters;
    }
    return TinkProtoParametersFormat.parse(getProto().toByteArray());
  }
}
