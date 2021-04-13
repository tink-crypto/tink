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
import com.google.crypto.tink.proto.testing.AeadDecryptRequest;
import com.google.crypto.tink.proto.testing.AeadDecryptResponse;
import com.google.crypto.tink.proto.testing.AeadEncryptRequest;
import com.google.crypto.tink.proto.testing.AeadEncryptResponse;
import com.google.crypto.tink.proto.testing.AeadGrpc.AeadImplBase;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implements a gRPC Aead Testing service. */
public final class AeadServiceImpl extends AeadImplBase {

  public AeadServiceImpl() throws GeneralSecurityException {
  }

  /** Encrypts a message. */
  @Override
  public void encrypt(
      AeadEncryptRequest request, StreamObserver<AeadEncryptResponse> responseObserver) {
    AeadEncryptResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Aead aead = keysetHandle.getPrimitive(Aead.class);
      byte[] ciphertext =
          aead.encrypt(
              request.getPlaintext().toByteArray(), request.getAssociatedData().toByteArray());
      response =
          AeadEncryptResponse.newBuilder().setCiphertext(ByteString.copyFrom(ciphertext)).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = AeadEncryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Decrypts a message. */
  @Override
  public void decrypt(
      AeadDecryptRequest request, StreamObserver<AeadDecryptResponse> responseObserver) {
    AeadDecryptResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Aead aead = keysetHandle.getPrimitive(Aead.class);
      byte[] plaintext =
          aead.decrypt(
              request.getCiphertext().toByteArray(), request.getAssociatedData().toByteArray());
      response =
          AeadDecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(plaintext)).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = AeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
