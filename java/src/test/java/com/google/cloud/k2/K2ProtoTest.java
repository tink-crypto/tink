package com.google.cloud.k2;

import static org.junit.Assert.assertEquals;

import com.google.cloud.k2.K2Proto.Keyset;

import org.junit.Test;

/**
 * A simple integration test to see whether protobuf is built correctly.
 */
public class K2ProtoTest {

  @Test
  public void testKeysetBasic() throws Exception {
    Keyset keyset = Keyset.newBuilder()
        .setPrimaryKeyId(1)
        .build();
    assertEquals(1, keyset.getPrimaryKeyId());
  }

}
