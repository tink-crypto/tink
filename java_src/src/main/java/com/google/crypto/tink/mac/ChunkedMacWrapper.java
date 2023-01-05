// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveSet.Entry;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.errorprone.annotations.Immutable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * ChunkedMacWrapper is the implementation of PrimitiveWrapper for the ChunkedMac primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To compute a MAC tag,
 * it uses the primary key in the keyset, and prepends to the tag a certain prefix associated with
 * the primary key. To verify a tag, the primitive uses the prefix of the tag to efficiently select
 * the right key in the set. If the keys associated with the prefix do not validate the tag, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class ChunkedMacWrapper implements PrimitiveWrapper<ChunkedMac, ChunkedMac> {

  private static final ChunkedMacWrapper WRAPPER = new ChunkedMacWrapper();

  private static class WrappedChunkedMacVerification implements ChunkedMacVerification {
    private final List<ChunkedMacVerification> verifications;

    private WrappedChunkedMacVerification(List<ChunkedMacVerification> verificationEntries) {
      this.verifications = verificationEntries;
    }

    @Override
    public void update(ByteBuffer data) throws GeneralSecurityException {
      // We will need to be `reset()`ting this buffer due to potentially multiple reads from the
      // same data span in order to be consistent with the behaviour of ChunkedMacComputation
      // wrapper. That is, after the execution, user's buffer's `mark` is left unchanged, and its
      // `position` is equal to `limit` after we finished reading from the buffer. In order to
      // achieve that we `duplicate()` the given `data` buffer here and set `mark()`s on the cloned
      // buffer (note that the `duplicate()` method does not copy the underlying data).
      ByteBuffer clonedData = data.duplicate();
      clonedData.mark();
      for (ChunkedMacVerification entry : verifications) {
        clonedData.reset();
        entry.update(clonedData);
      }
      data.position(data.limit());
    }

    @Override
    public void verifyMac() throws GeneralSecurityException {
      GeneralSecurityException errorSink =
          new GeneralSecurityException("MAC verification failed for all suitable keys in keyset");
      for (ChunkedMacVerification entry : verifications) {
        try {
          entry.verifyMac();
          // If there is no exception, the MAC is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored as we want to continue verification with the remaining keys.
          errorSink.addSuppressed(e);
        }
      }
      // nothing works.
      throw errorSink;
    }
  }

  @Immutable
  private static class WrappedChunkedMac implements ChunkedMac {
    @SuppressWarnings("Immutable") // We never change the primitives set.
    private final PrimitiveSet<ChunkedMac> primitives;

    private WrappedChunkedMac(PrimitiveSet<ChunkedMac> primitives) {
      this.primitives = primitives;
    }

    @Override
    public ChunkedMacComputation createComputation() throws GeneralSecurityException {
      return getChunkedMac(primitives.getPrimary()).createComputation();
    }

    private ChunkedMac getChunkedMac(Entry<ChunkedMac> entry) {
      return entry.getFullPrimitive();
    }

    @Override
    public ChunkedMacVerification createVerification(final byte[] tag)
        throws GeneralSecurityException {
      byte[] prefix = Arrays.copyOf(tag, CryptoFormat.NON_RAW_PREFIX_SIZE);

      // First add verifications with prefixed keys.
      List<ChunkedMacVerification> verifications = new ArrayList<>();
      for (PrimitiveSet.Entry<ChunkedMac> primitive : primitives.getPrimitive(prefix)) {
        verifications.add(getChunkedMac(primitive).createVerification(tag));
      }
      // Also add verifications with non-prefixed keys.
      for (PrimitiveSet.Entry<ChunkedMac> primitive : primitives.getRawPrimitives()) {
        verifications.add(getChunkedMac(primitive).createVerification(tag));
      }

      return new WrappedChunkedMacVerification(verifications);
    }
  }

  private ChunkedMacWrapper() {}

  @Override
  public ChunkedMac wrap(final PrimitiveSet<ChunkedMac> primitives)
      throws GeneralSecurityException {
    if (primitives == null) {
      throw new GeneralSecurityException("primitive set must be non-null");
    }
    if (primitives.getPrimary() == null) {
      throw new GeneralSecurityException("no primary in primitive set");
    }
    for (List<PrimitiveSet.Entry<ChunkedMac>> list : primitives.getAll()) {
      for (PrimitiveSet.Entry<ChunkedMac> entry : list) {
        // Ensure that all entries in the primitive set are present and valid (i.e. have
        // `fullPrimitive` field set). Throws unchecked exceptions if it's not the case.
        ChunkedMac unused = entry.getFullPrimitive();
      }
    }
    return new WrappedChunkedMac(primitives);
  }

  @Override
  public Class<ChunkedMac> getPrimitiveClass() {
    return ChunkedMac.class;
  }

  @Override
  public Class<ChunkedMac> getInputPrimitiveClass() {
    return ChunkedMac.class;
  }

  static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(WRAPPER);
  }
}
