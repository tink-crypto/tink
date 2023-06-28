// Copyright 2023 Google LLC
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
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Functions to parse and serialize Parameters in Tink's binary format based on Protobufs. */
public final class TinkProtoParametersFormat {
  /**
   * Serializes a parameters object into a byte[] according to Tink's binary format.
   */
  public static byte[] serialize(Parameters parameters) throws GeneralSecurityException {
    if (parameters instanceof LegacyProtoParameters) {
      return ((LegacyProtoParameters) parameters).getSerialization().getKeyTemplate().toByteArray();
    }
    ProtoParametersSerialization s =
        MutableSerializationRegistry.globalInstance()
            .serializeParameters(parameters, ProtoParametersSerialization.class);
    return s.getKeyTemplate().toByteArray();
  }

  /**
   * Parses a byte[] into a parameters object into a byte[] according to Tink's binary format.
   */
  public static Parameters parse(byte[] serializedParameters) throws GeneralSecurityException {
    KeyTemplate t;
    try {
      t = KeyTemplate.parseFrom(serializedParameters, ExtensionRegistryLite.getEmptyRegistry());
    } catch (IOException e) {
      throw new GeneralSecurityException("Failed to parse proto", e);
    }
    return MutableSerializationRegistry.globalInstance()
        .parseParametersWithLegacyFallback(ProtoParametersSerialization.checkedCreate(t));
  }

  private TinkProtoParametersFormat() {}
}
