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
package com.google.crypto.tink.prf;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PrfSetWrapper is the implementation of PrimitiveWrapper for the PrfSet primitive.
 *
 * <p>The returned primitive has instances of {@code Prf} for each key in the KeySet. The individual
 * Prf instances can then be used to compute psuedo-random sequences from the underlying key.
 */
@Immutable
public class PrfSetWrapper implements PrimitiveWrapper<Prf, PrfSet> {
  private static class WrappedPrfSet extends PrfSet {
    // This map is constructed using Collections.unmodifiableMap
    @SuppressWarnings("Immutable")
    private final Map<Integer, Prf> keyIdToPrfMap;

    private final int primaryKeyId;

    private WrappedPrfSet(PrimitiveSet<Prf> primitives) throws GeneralSecurityException {
      if (primitives.getRawPrimitives().isEmpty()) {
        throw new GeneralSecurityException("No primitives provided.");
      }
      if (primitives.getPrimary() == null) {
        throw new GeneralSecurityException("Primary key not set.");
      }

      primaryKeyId = primitives.getPrimary().getKeyId();
      List<PrimitiveSet.Entry<Prf>> entries = primitives.getRawPrimitives();
      Map<Integer, Prf> mutablePrfMap = new HashMap<>();
      for (PrimitiveSet.Entry<Prf> entry : entries) {
        if (!entry.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
          throw new GeneralSecurityException(
              "Key " + entry.getKeyId() + " has non raw prefix type");
        }
        // Likewise, the key IDs of the PrfSet passed
        mutablePrfMap.put(entry.getKeyId(), entry.getPrimitive());
      }
      keyIdToPrfMap = Collections.unmodifiableMap(mutablePrfMap);
    }

    @Override
    public int getPrimaryId() {
      return primaryKeyId;
    }

    @Override
    public Map<Integer, Prf> getPrfs() throws GeneralSecurityException {
      return keyIdToPrfMap;
    }
  }

  @Override
  public PrfSet wrap(PrimitiveSet<Prf> set) throws GeneralSecurityException {
    return new WrappedPrfSet(set);
  }

  @Override
  public Class<PrfSet> getPrimitiveClass() {
    return PrfSet.class;
  }

  @Override
  public Class<Prf> getInputPrimitiveClass() {
    return Prf.class;
  }

  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new PrfSetWrapper());
  }
}
