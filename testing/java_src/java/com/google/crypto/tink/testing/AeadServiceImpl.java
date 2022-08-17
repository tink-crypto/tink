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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.testing.proto.AeadDecryptRequest;
import com.google.crypto.tink.testing.proto.AeadDecryptResponse;
import com.google.crypto.tink.testing.proto.AeadEncryptRequest;
import com.google.crypto.tink.testing.proto.AeadEncryptResponse;
import com.google.crypto.tink.testing.proto.AeadGrpc.AeadImplBase;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implements a gRPC Aead Testing service. */
public final class AeadServiceImpl extends AeadImplBase {

  public AeadServiceImpl() throws GeneralSecurityException {}

  @Override
  public void create(CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      keysetHandle.getPrimitive(Aead.class);
    } catch (GeneralSecurityException | IOException e) {
      responseObserver.onNext(CreationResponse.newBuilder().setErr(e.toString()).build());
      responseObserver.onCompleted();
      return;
    }
    responseObserver.onNext(CreationResponse.getDefaultInstance());
    responseObserver.onCompleted();
  }

  AeadEncryptResponse encryptWithAead(Aead aead, byte[] plaintext, byte[] associatedData) {
    try {
      byte[] ciphertext = aead.encrypt(plaintext, associatedData);
      return AeadEncryptResponse.newBuilder()
          .setCiphertext(ByteString.copyFrom(ciphertext))
          .build();
    } catch (GeneralSecurityException e) {
      return AeadEncryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  AeadDecryptResponse decryptWithAead(Aead aead, byte[] ciphertext, byte[] associatedData) {
    try {
      byte[] plaintext = aead.decrypt(ciphertext, associatedData);
      return AeadDecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(plaintext)).build();
    } catch (GeneralSecurityException e) {
      return AeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  /** Encrypts a message. */
  @Override
  public void encrypt(
      AeadEncryptRequest request, StreamObserver<AeadEncryptResponse> responseObserver) {
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Aead aead = keysetHandle.getPrimitive(Aead.class);
      AeadEncryptResponse response =
          encryptWithAead(
              aead,
              request.getPlaintext().toByteArray(),
              request.getAssociatedData().toByteArray());
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }

  /** Decrypts a message. */
  @Override
  public void decrypt(
      AeadDecryptRequest request, StreamObserver<AeadDecryptResponse> responseObserver) {
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Aead aead = keysetHandle.getPrimitive(Aead.class);
      AeadDecryptResponse response =
          decryptWithAead(
              aead,
              request.getCiphertext().toByteArray(),
              request.getAssociatedData().toByteArray());
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
