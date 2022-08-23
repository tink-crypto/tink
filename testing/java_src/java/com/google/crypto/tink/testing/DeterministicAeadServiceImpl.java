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

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadDecryptRequest;
import com.google.crypto.tink.testing.proto.DeterministicAeadDecryptResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadEncryptRequest;
import com.google.crypto.tink.testing.proto.DeterministicAeadEncryptResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadGrpc.DeterministicAeadImplBase;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/** Implements a gRPC DeterministicAead Testing service. */
public final class DeterministicAeadServiceImpl extends DeterministicAeadImplBase {

  public DeterministicAeadServiceImpl() throws GeneralSecurityException {}

  @Override
  public void create(CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    Util.createPrimitiveForRpc(request, responseObserver, DeterministicAead.class);
  }

  private DeterministicAeadEncryptResponse encryptDeterministically(
      DeterministicAeadEncryptRequest request) throws GeneralSecurityException {
    DeterministicAead daead =
        Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(DeterministicAead.class);
    try {
      byte[] ciphertext =
          daead.encryptDeterministically(
              request.getPlaintext().toByteArray(), request.getAssociatedData().toByteArray());
      return DeterministicAeadEncryptResponse.newBuilder()
          .setCiphertext(ByteString.copyFrom(ciphertext))
          .build();
    } catch (GeneralSecurityException e) {
      return DeterministicAeadEncryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void encryptDeterministically(
      DeterministicAeadEncryptRequest request,
      StreamObserver<DeterministicAeadEncryptResponse> responseObserver) {
    try {
      DeterministicAeadEncryptResponse response = encryptDeterministically(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }

  private DeterministicAeadDecryptResponse decryptDeterministically(
      DeterministicAeadDecryptRequest request) throws GeneralSecurityException {
    DeterministicAead daead =
        Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(DeterministicAead.class);
    try {
      byte[] plaintext =
          daead.decryptDeterministically(
              request.getCiphertext().toByteArray(), request.getAssociatedData().toByteArray());
      return DeterministicAeadDecryptResponse.newBuilder()
          .setPlaintext(ByteString.copyFrom(plaintext))
          .build();
    } catch (GeneralSecurityException e) {
      return DeterministicAeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void decryptDeterministically(
      DeterministicAeadDecryptRequest request,
      StreamObserver<DeterministicAeadDecryptResponse> responseObserver) {
    try {
      DeterministicAeadDecryptResponse response = decryptDeterministically(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
