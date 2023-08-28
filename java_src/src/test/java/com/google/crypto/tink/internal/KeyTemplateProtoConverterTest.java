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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests KeyTemplateProtoConverter. */
@RunWith(JUnit4.class)
public final class KeyTemplateProtoConverterTest {
  @BeforeClass
  public static void registerTink() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void toByteArrayTheParse_sameValues() throws Exception {
    KeyTemplate template = AesGcmKeyManager.aes128GcmTemplate();
    byte[] bytes = KeyTemplateProtoConverter.toByteArray(template);
    Parameters parameters = TinkProtoParametersFormat.parse(bytes);
    assertThat(template.toParameters()).isEqualTo(parameters);
  }
}
