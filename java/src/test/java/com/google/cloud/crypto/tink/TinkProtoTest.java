package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertEquals;

import com.google.cloud.crypto.tink.TinkProto.Keyset;

import org.junit.Test;

/**
 * A simple integration test to see whether protobuf is built correctly.
 */
public class TinkProtoTest {

  @Test
  public void testKeysetBasic() throws Exception {
    Keyset keyset = Keyset.newBuilder()
        .setPrimaryKeyId(1)
        .build();
    assertEquals(1, keyset.getPrimaryKeyId());
  }

}
