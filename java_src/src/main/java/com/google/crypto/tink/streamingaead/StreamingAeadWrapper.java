// Copyright 2017 Google LLC
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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.streamingaead.internal.LegacyFullStreamingAead;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * StreamingAeadWrapper is the implementation of PrimitiveWrapper for the StreamingAead primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset. To decrypt, the primitive tries the enabled keys from the
 * keyset to select the right key for decryption. All keys in a keyset of StreamingAead have type
 * {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class StreamingAeadWrapper implements PrimitiveWrapper<StreamingAead, StreamingAead> {

  private static final StreamingAeadWrapper WRAPPER = new StreamingAeadWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, StreamingAead>
      LEGACY_FULL_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullStreamingAead::create, LegacyProtoKey.class, StreamingAead.class);

  StreamingAeadWrapper() {}

  /**
   * @return a StreamingAead primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  @Override
  public StreamingAead wrap(final PrimitiveSet<StreamingAead> primitives)
      throws GeneralSecurityException {
    List<StreamingAead> allStreamingAeads = new ArrayList<>();
    for (List<PrimitiveSet.Entry<StreamingAead>> entryList : primitives.getAll()) {
      // For legacy reasons (Tink always encrypted with non-RAW keys) we use all
      // primitives, even those which have output_prefix_type != RAW.
      for (PrimitiveSet.Entry<StreamingAead> entry : entryList) {
        if (entry.getFullPrimitive() == null) {
          throw new GeneralSecurityException(
              "No full primitive set for key id " + entry.getKeyId());
        }
        allStreamingAeads.add(entry.getFullPrimitive());
      }
    }
    PrimitiveSet.Entry<StreamingAead> primary = primitives.getPrimary();
    if (primary == null || primary.getFullPrimitive() == null) {
      throw new GeneralSecurityException("No primary set");
    }
    return new StreamingAeadHelper(allStreamingAeads, primary.getFullPrimitive());
  }

  @Override
  public Class<StreamingAead> getPrimitiveClass() {
    return StreamingAead.class;
  }

  @Override
  public Class<StreamingAead> getInputPrimitiveClass() {
    return StreamingAead.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_STREAMING_AEAD_PRIMITIVE_CONSTRUCTOR);
  }
}
