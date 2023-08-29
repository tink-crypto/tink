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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.security.GeneralSecurityException;

/** KeyTemplateProtoConverter converts KeyTemplate to and from the binary proto format. */
public final class KeyTemplateProtoConverter {

  public static KeyTemplate.OutputPrefixType prefixFromProto(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return KeyTemplate.OutputPrefixType.TINK;
      case LEGACY:
        return KeyTemplate.OutputPrefixType.LEGACY;
      case RAW:
        return KeyTemplate.OutputPrefixType.RAW;
      case CRUNCHY:
        return KeyTemplate.OutputPrefixType.CRUNCHY;
      default:
        throw new GeneralSecurityException("Unknown output prefix type");
    }
  }

  public static com.google.crypto.tink.proto.KeyTemplate toProto(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    Parameters parameters = keyTemplate.toParameters();
    if (parameters instanceof LegacyProtoParameters) {
      return ((LegacyProtoParameters) parameters).getSerialization().getKeyTemplate();
    }
    ProtoParametersSerialization s =
        MutableSerializationRegistry.globalInstance()
            .serializeParameters(parameters, ProtoParametersSerialization.class);
    return s.getKeyTemplate();
  }

  public static byte[] toByteArray(KeyTemplate keyTemplate) throws GeneralSecurityException {
    return toProto(keyTemplate).toByteArray();
  }

  public static KeyTemplate.OutputPrefixType getOutputPrefixType(KeyTemplate t)
      throws GeneralSecurityException {
    return prefixFromProto(toProto(t).getOutputPrefixType());
  }

  private KeyTemplateProtoConverter() {}
}
