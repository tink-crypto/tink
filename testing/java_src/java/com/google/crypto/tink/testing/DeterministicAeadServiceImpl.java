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

import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.testing.proto.DeterministicAeadDecryptRequest;
import com.google.crypto.tink.testing.proto.DeterministicAeadDecryptResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadEncryptRequest;
import com.google.crypto.tink.testing.proto.DeterministicAeadEncryptResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadGrpc.DeterministicAeadImplBase;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implements a gRPC DeterministicAead Testing service. */
public final class DeterministicAeadServiceImpl extends DeterministicAeadImplBase {

  public DeterministicAeadServiceImpl() throws GeneralSecurityException {
  }

  /** Encrypts a message. */
  @Override
  public void encryptDeterministically(
      DeterministicAeadEncryptRequest request,
      StreamObserver<DeterministicAeadEncryptResponse> responseObserver) {
    DeterministicAeadEncryptResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);
      byte[] ciphertext =
          daead.encryptDeterministically(
              request.getPlaintext().toByteArray(), request.getAssociatedData().toByteArray());
      response =
          DeterministicAeadEncryptResponse.newBuilder()
              .setCiphertext(ByteString.copyFrom(ciphertext))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = DeterministicAeadEncryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Decrypts a message. */
  @Override
  public void decryptDeterministically(
      DeterministicAeadDecryptRequest request,
      StreamObserver<DeterministicAeadDecryptResponse> responseObserver) {
    DeterministicAeadDecryptResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);
      byte[] plaintext =
          daead.decryptDeterministically(
              request.getCiphertext().toByteArray(), request.getAssociatedData().toByteArray());
      response =
          DeterministicAeadDecryptResponse.newBuilder()
              .setPlaintext(ByteString.copyFrom(plaintext))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = DeterministicAeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
