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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.HybridDecryptRequest;
import com.google.crypto.tink.testing.proto.HybridDecryptResponse;
import com.google.crypto.tink.testing.proto.HybridEncryptRequest;
import com.google.crypto.tink.testing.proto.HybridEncryptResponse;
import com.google.crypto.tink.testing.proto.HybridGrpc.HybridImplBase;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/** Implements a gRPC Hybrid Encryption Testing service. */
public final class HybridServiceImpl extends HybridImplBase {

  public HybridServiceImpl() throws GeneralSecurityException {}

  @Override
  public void createHybridEncrypt(
      CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    Util.createPrimitiveForRpc(request, responseObserver, HybridEncrypt.class);
  }

  @Override
  public void createHybridDecrypt(
      CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    Util.createPrimitiveForRpc(request, responseObserver, HybridDecrypt.class);
  }


  private HybridEncryptResponse encrypt(HybridEncryptRequest request)
      throws GeneralSecurityException {
    try {
      // TODO(b/241219877) Move the next line out from the try-catch block.
      HybridEncrypt hybridEncrypt =
          Util.parseBinaryProtoKeyset(request.getPublicKeyset()).getPrimitive(HybridEncrypt.class);
      byte[] ciphertext =
          hybridEncrypt.encrypt(
              request.getPlaintext().toByteArray(), request.getContextInfo().toByteArray());
      return HybridEncryptResponse.newBuilder()
          .setCiphertext(ByteString.copyFrom(ciphertext))
          .build();
    } catch (GeneralSecurityException e) {
      return HybridEncryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void encrypt(
      HybridEncryptRequest request, StreamObserver<HybridEncryptResponse> responseObserver) {
    try {
      HybridEncryptResponse response = encrypt(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }

  private HybridDecryptResponse decrypt(HybridDecryptRequest request)
      throws GeneralSecurityException {
    try {
      // TODO(b/241219877) Move the next line out from the try-catch block.
      HybridDecrypt hybridDecrypt =
          Util.parseBinaryProtoKeyset(request.getPrivateKeyset()).getPrimitive(HybridDecrypt.class);
      byte[] plaintext =
          hybridDecrypt.decrypt(
              request.getCiphertext().toByteArray(), request.getContextInfo().toByteArray());
      return HybridDecryptResponse.newBuilder()
          .setPlaintext(ByteString.copyFrom(plaintext))
          .build();
    } catch (GeneralSecurityException e) {
      return HybridDecryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void decrypt(
      HybridDecryptRequest request, StreamObserver<HybridDecryptResponse> responseObserver) {
    try {
      HybridDecryptResponse response = decrypt(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }
}
