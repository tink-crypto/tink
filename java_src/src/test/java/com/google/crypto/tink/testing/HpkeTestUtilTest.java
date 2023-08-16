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

package com.google.crypto.tink.testing;

import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code HpkeTestUtil}. */
@RunWith(JUnit4.class)
public final class HpkeTestUtilTest {

  private static final String INFO = "4f6465206f6e2061204772656369616e2055726e";
  private static final String SENDER_EPHEMERAL_PUBLIC_KEY =
      "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
  private static final String SENDER_EPHEMERAL_PRIVATE_KEY =
      "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
  private static final String SENDER_PUBLIC_KEY =
      "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b";
  private static final String SENDER_PRIVATE_KEY =
      "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd";
  private static final String RECIPIENT_PUBLIC_KEY =
      "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
  private static final String RECIPIENT_PRIVATE_KEY =
      "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
  private static final String ENCAPSULATED_KEY =
      "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
  private static final String SHARED_SECRET =
      "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
  private static final String KEY_SCHEDULE_CONTEXT =
      "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449";
  private static final String SECRET =
      "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397";
  private static final String KEY = "4531685d41d65f03dc48f6b8302c05b0";
  private static final String BASE_NONCE = "56d890e5accaaf011cff4b7d";

  @Test
  public void buildBaseModeHpkeTestSetup_shouldSucceed() throws Exception {
    HpkeTestSetup unused =
        HpkeTestSetup.builder()
            .setInfo(INFO)
            .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
            .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
            .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
            .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
            .setEncapsulatedKey(ENCAPSULATED_KEY)
            .setSharedSecret(SHARED_SECRET)
            .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
            .setSecret(SECRET)
            .setKey(KEY)
            .setBaseNonce(BASE_NONCE)
            .build();
  }

  @Test
  public void buildAuthModeHpkeTestSetup_shouldSucceed() throws Exception {
    HpkeTestSetup unused =
        HpkeTestSetup.builder()
            .setInfo(INFO)
            .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
            .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
            .setSenderPublicKey(SENDER_PUBLIC_KEY)
            .setSenderPrivateKey(SENDER_PRIVATE_KEY)
            .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
            .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
            .setEncapsulatedKey(ENCAPSULATED_KEY)
            .setSharedSecret(SHARED_SECRET)
            .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
            .setSecret(SECRET)
            .setKey(KEY)
            .setBaseNonce(BASE_NONCE)
            .build();
  }

  @Test
  public void buildEmptyHpkeTestSetup_shouldThrowInvalidArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> HpkeTestSetup.builder().build());
  }

  @Test
  public void buildHpkeTestSetupWithoutInfo_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void
      buildHpkeTestSetupWithoutSenderEphemeralPublicKey_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void
      buildHpkeTestSetupWithoutSenderEphemeralPrivateKey_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutRecipientPublicKey_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutRecipientPrivateKey_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutEncapsulatedKey_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutSharedSecret_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutKeyScheduleContext_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setSecret(SECRET)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutSecret_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setKey(KEY)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutKey_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setBaseNonce(BASE_NONCE)
                .build());
  }

  @Test
  public void buildHpkeTestSetupWithoutBaseNonce_shouldThrowInvalidArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            HpkeTestSetup.builder()
                .setInfo(INFO)
                .setSenderEphemeralPublicKey(SENDER_EPHEMERAL_PUBLIC_KEY)
                .setSenderEphemeralPrivateKey(SENDER_EPHEMERAL_PRIVATE_KEY)
                .setRecipientPublicKey(RECIPIENT_PUBLIC_KEY)
                .setRecipientPrivateKey(RECIPIENT_PRIVATE_KEY)
                .setEncapsulatedKey(ENCAPSULATED_KEY)
                .setSharedSecret(SHARED_SECRET)
                .setKeyScheduleContext(KEY_SCHEDULE_CONTEXT)
                .setSecret(SECRET)
                .setKey(KEY)
                .build());
  }
}
