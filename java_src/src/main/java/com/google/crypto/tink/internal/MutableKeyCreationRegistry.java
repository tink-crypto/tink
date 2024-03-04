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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/** Stores methods to create {@link Key} objects from {@link Parameters} with new randomness. */
public final class MutableKeyCreationRegistry {
  private final Map<Class<? extends Parameters>, KeyCreator<? extends Parameters>> creators =
      new HashMap<>();

  /** A class to create key objects from parameters with given randomness. */
  public static interface KeyCreator<ParametersT extends Parameters> {
    public Key createKey(ParametersT parameters, @Nullable Integer idRequirement)
        throws GeneralSecurityException;
  }

  private static LegacyProtoKey createProtoKeyFromProtoParmaeters(
      LegacyProtoParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    KeyTemplate keyTemplate = parameters.getSerialization().getKeyTemplate();
    KeyManager<?> manager =
        KeyManagerRegistry.globalInstance().getUntypedKeyManager(keyTemplate.getTypeUrl());
    if (!KeyManagerRegistry.globalInstance().isNewKeyAllowed(keyTemplate.getTypeUrl())) {
      throw new GeneralSecurityException("Creating new keys is not allowed.");
    }
    KeyData keyData = manager.newKeyData(keyTemplate.getValue());
    ProtoKeySerialization protoSerialization =
        ProtoKeySerialization.create(
            keyData.getTypeUrl(),
            keyData.getValue(),
            keyData.getKeyMaterialType(),
            keyTemplate.getOutputPrefixType(),
            idRequirement);
    return new LegacyProtoKey(protoSerialization, InsecureSecretKeyAccess.get());
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<LegacyProtoParameters>
      LEGACY_PROTO_KEY_CREATOR = MutableKeyCreationRegistry::createProtoKeyFromProtoParmaeters;

  private static MutableKeyCreationRegistry newRegistryWithLegacyFallback() {
    MutableKeyCreationRegistry registry = new MutableKeyCreationRegistry();
    try {
      registry.add(LEGACY_PROTO_KEY_CREATOR, LegacyProtoParameters.class);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("unexpected error.", e);
    }
    return registry;
  }

  private static final MutableKeyCreationRegistry globalInstance = newRegistryWithLegacyFallback();

  public static MutableKeyCreationRegistry globalInstance() {
    return globalInstance;
  }

  /**
   * Adds a new "InsecureKeyCreator" to the instance.
   *
   * <p>If a creator for this class has been added previously, the two instances have to be equal.
   * Otherwise, this method throws a {@code GeneralSecurityException}.
   */
  public synchronized <ParametersT extends Parameters> void add(
      KeyCreator<ParametersT> creator, Class<ParametersT> parametersClass)
      throws GeneralSecurityException {
    KeyCreator<?> existingCreator = creators.get(parametersClass);
    if (existingCreator != null) {
      if (!existingCreator.equals(creator)) {
        throw new GeneralSecurityException(
            "Different key creator for parameters class " + parametersClass + " already inserted");
      }
    }
    creators.put(parametersClass, creator);
  }

  /**
   * Creates a {@link Key} from a given {@link Parameters} object.
   *
   * <p>Finds the previously added creator (with {@link #add}) for the class given by {@code
   * parameters.getClass()} and uses it.
   */
  public Key createKey(Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return createKeyTyped(parameters, idRequirement);
  }

  // Separate function to hide use of generics in the above public function.
  private synchronized <ParametersT extends Parameters> Key createKeyTyped(
      ParametersT parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    Class<?> parametersClass = parameters.getClass();
    KeyCreator<?> creator = creators.get(parametersClass);
    if (creator == null) {
      throw new GeneralSecurityException(
          "Cannot create a new key for parameters "
              + parameters
              + ": no key creator for this class was registered.");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    KeyCreator<ParametersT> castCreator = (KeyCreator<ParametersT>) creator;
    return castCreator.createKey(parameters, idRequirement);
  }
}
