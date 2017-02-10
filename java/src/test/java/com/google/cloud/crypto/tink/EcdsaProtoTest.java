package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertEquals;

import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPublicKey;

import org.junit.Test;

/**
 * A simple integration test to see whether Ecdsa protobuf is built correctly.
 * TODO(quannguyen): Add extensive tests.
 */
public class EcdsaProtoTest {

  @Test
  public void testKeysetBasic() throws Exception {
    EcdsaPublicKey publicKey = EcdsaPublicKey.newBuilder().setVersion(1).build();
    assertEquals(1, publicKey.getVersion());
  }
}
