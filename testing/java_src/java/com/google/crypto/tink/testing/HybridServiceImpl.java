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
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.testing.proto.HybridDecryptRequest;
import com.google.crypto.tink.testing.proto.HybridDecryptResponse;
import com.google.crypto.tink.testing.proto.HybridEncryptRequest;
import com.google.crypto.tink.testing.proto.HybridEncryptResponse;
import com.google.crypto.tink.testing.proto.HybridGrpc.HybridImplBase;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implements a gRPC Hybrid Encryption Testing service. */
public final class HybridServiceImpl extends HybridImplBase {

  public HybridServiceImpl() throws GeneralSecurityException {
  }

  /** Encrypts a message. */
  @Override
  public void encrypt(
      HybridEncryptRequest request, StreamObserver<HybridEncryptResponse> responseObserver) {
    HybridEncryptResponse response;
    try {
      KeysetHandle publicKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getPublicKeyset().toByteArray()));
      HybridEncrypt hybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt.class);
      byte[] ciphertext =
          hybridEncrypt.encrypt(
              request.getPlaintext().toByteArray(), request.getContextInfo().toByteArray());
      response =
          HybridEncryptResponse.newBuilder().setCiphertext(ByteString.copyFrom(ciphertext)).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = HybridEncryptResponse.newBuilder().setErr(e.toString()).build();
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
      HybridDecryptRequest request, StreamObserver<HybridDecryptResponse> responseObserver) {
    HybridDecryptResponse response;
    try {
      KeysetHandle privateKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getPrivateKeyset().toByteArray()));
      HybridDecrypt hybridDecrypt = privateKeysetHandle.getPrimitive(HybridDecrypt.class);
      byte[] plaintext =
          hybridDecrypt.decrypt(
              request.getCiphertext().toByteArray(), request.getContextInfo().toByteArray());
      response =
          HybridDecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(plaintext)).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = HybridDecryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
