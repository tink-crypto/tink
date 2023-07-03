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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.keyderivation.internal.PrfBasedDeriverKeyManager;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.crypto.tink.proto.PrfBasedDeriverParams;
import java.security.GeneralSecurityException;

/**
 * Generates {@link com.google.crypto.tink.KeyTemplate} for the {@link KeysetDeriver} primitive.
 *
 * <p>We recommend to avoid this class in order to keep dependencies small.
 *
 * <ul>
 *   <li>Using this class adds a dependency on protobuf. We hope that eventually it is possible to
 *       use Tink without a dependency on protobuf.
 *   <li>Using this class adds a dependency on classes for all involved key types.
 * </ul>
 *
 * These dependencies all come from static class member variables, which are initialized when the
 * class is loaded. This implies that static analysis and code minimization tools (such as proguard)
 * cannot remove the usages either.
 *
 * <p>Instead, we recommend to use {@code KeysetHandle.generateEntryFromParametersName} or {@code
 * KeysetHandle.generateEntryFromParameters}.
 *
 * <p>One can use these templates to generate new {@link com.google.crypto.tink.proto.Keyset} with
 * {@link KeysetHandle#generateNew}. To generate a new keyset that uses the HKDF_SHA256 PRF to
 * derive a AES256_GCM keyset, one can do:
 *
 * <pre>{@code
 * KeyTemplate template = KeyDerivationKeyTemplates.createPrfBasedKeyTemplate(
 *     KeyTemplates.get("HKDF_SHA256"), KeyTemplates.get("AES256_GCM"));
 * KeysetHandle handle = KeysetHandle.generateNew(template);
 * KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);
 * }</pre>
 *
 * @since 1.0.0
 */
public final class KeyDerivationKeyTemplates {
  /**
   * Returns a {@link KeyTemplate} containing a {@link PrfBasedDeriverKeyFormat}.
   *
   * <p>Creates a key template for key derivation that uses a PRF to derive a key that adheres to
   * {@code derivedKeyTemplate}. The following must be true:
   *
   * <ol>
   *   <li>{@code prfKeyTemplate} is a PRF key template, i.e. {@code
   *       handle.getPrimitive(StreamingPrf.class)} works.
   *   <li>{@code derivedKeyTemplate} describes a key type that supports derivation.
   * </ol>
   *
   * <p>The output prefix type of the derived key will match the output prefix type of {@code
   * derivedKeyTemplate}. This function verifies the newly created key template by creating a
   * KeysetDeriver primitive from it. This requires both the {@code prfKeyTemplate} and {@code
   * derivedKeyTemplate} key types to be in the registry. It also attempts to derive a key,
   * returning an error on failure.
   */
  public static KeyTemplate createPrfBasedKeyTemplate(
      KeyTemplate prfKeyTemplate, KeyTemplate derivedKeyTemplate) throws GeneralSecurityException {
    PrfBasedDeriverKeyFormat format =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(toKeyTemplateProto(prfKeyTemplate))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(toKeyTemplateProto(derivedKeyTemplate)))
            .build();
    KeyTemplate template =
        KeyTemplate.create(
            new PrfBasedDeriverKeyManager().getKeyType(),
            format.toByteArray(),
            derivedKeyTemplate.getOutputPrefixType());
    // Verify {@code template} is derivable.
    KeysetHandle unused = KeysetHandle.generateNew(template);
    return template;
  }

  private static com.google.crypto.tink.proto.KeyTemplate toKeyTemplateProto(
      KeyTemplate keyTemplate) throws GeneralSecurityException {
    return KeyTemplateProtoConverter.toProto(keyTemplate);
  }

  private KeyDerivationKeyTemplates() {}
}
