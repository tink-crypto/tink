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
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/** KeyTemplateProtoConverter converts KeyTemplate to and from the binary proto format. */
public final class KeyTemplateProtoConverter {

  private static KeyTemplate.OutputPrefixType fromProto(
      OutputPrefixType outputPrefixType) {
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
        throw new IllegalArgumentException("Unknown output prefix type");
    }
  }

  private static OutputPrefixType toProto(
      KeyTemplate.OutputPrefixType outputPrefixType) {
    switch (outputPrefixType) {
      case TINK:
        return OutputPrefixType.TINK;
      case LEGACY:
        return OutputPrefixType.LEGACY;
      case RAW:
        return OutputPrefixType.RAW;
      case CRUNCHY:
        return OutputPrefixType.CRUNCHY;
    }
    throw new IllegalArgumentException("Unknown output prefix type");
  }

  public static byte[] toByteArray(KeyTemplate keyTemplate) {
    return com.google.crypto.tink.proto.KeyTemplate.newBuilder()
        .setTypeUrl(keyTemplate.getTypeUrl())
        .setValue(ByteString.copyFrom(keyTemplate.getValue()))
        .setOutputPrefixType(toProto(keyTemplate.getOutputPrefixType()))
        .build()
        .toByteArray();
  }

  public static KeyTemplate fromByteArray(byte[] bytes) throws GeneralSecurityException {
    try {
      com.google.crypto.tink.proto.KeyTemplate kt =
          com.google.crypto.tink.proto.KeyTemplate.parseFrom(
              bytes, ExtensionRegistryLite.getEmptyRegistry());
      return KeyTemplate.create(
          kt.getTypeUrl(),
          kt.getValue().toByteArray(),
          fromProto(kt.getOutputPrefixType()));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid key template", e);
    }
  }

  private KeyTemplateProtoConverter() {
  }
}
