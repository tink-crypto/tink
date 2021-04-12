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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests KeyTemplateProtoConverter. */
@RunWith(JUnit4.class)
public final class KeyTemplateProtoConverterTest {

  @Test
  public void toByteArrayFromByteArray_sameValues() throws Exception {
    KeyTemplate template = AesGcmKeyManager.aes128GcmTemplate();
    byte[] bytes = KeyTemplateProtoConverter.toByteArray(template);
    KeyTemplate template2 = KeyTemplateProtoConverter.fromByteArray(bytes);
    assertThat(template.getTypeUrl()).isEqualTo(template2.getTypeUrl());
    assertThat(template.getValue()).isEqualTo(template2.getValue());
    assertThat(template.getOutputPrefixType()).isEqualTo(template2.getOutputPrefixType());
  }

  @Test
  public void unknownOutputPrefix_throwsGeneralSecurityException() throws Exception {
    byte[] templateBytes = KeyTemplateProtoConverter.toByteArray(
        AesGcmKeyManager.aes128GcmTemplate());
    com.google.crypto.tink.proto.KeyTemplate templateProto =
          com.google.crypto.tink.proto.KeyTemplate.parseFrom(
              templateBytes, ExtensionRegistryLite.getEmptyRegistry());
    byte[] invalidTemplateBytes = templateProto.toBuilder()
        .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX).build().toByteArray();
    assertThrows(
        GeneralSecurityException.class,
        () -> {
          KeyTemplateProtoConverter.fromByteArray(invalidTemplateBytes);
        });
  }

  @Test
  public void fromBadByteArray_throwsException() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> {
          KeyTemplateProtoConverter.fromByteArray("bad template".getBytes(UTF_8));
        });
  }
}
