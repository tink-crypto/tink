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
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.testing.proto.SignatureGrpc.SignatureImplBase;
import com.google.crypto.tink.testing.proto.SignatureSignRequest;
import com.google.crypto.tink.testing.proto.SignatureSignResponse;
import com.google.crypto.tink.testing.proto.SignatureVerifyRequest;
import com.google.crypto.tink.testing.proto.SignatureVerifyResponse;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implements a gRPC Signature Testing service. */
public final class SignatureServiceImpl extends SignatureImplBase {

  public SignatureServiceImpl() throws GeneralSecurityException {
  }

  /** Signs a message. */
  @Override
  public void sign(
      SignatureSignRequest request,
      StreamObserver<SignatureSignResponse> responseObserver) {
    SignatureSignResponse response;
    try {
      KeysetHandle privateKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getPrivateKeyset().toByteArray()));
      PublicKeySign signer = privateKeysetHandle.getPrimitive(PublicKeySign.class);
      byte[] signatureValue = signer.sign(request.getData().toByteArray());
      response = SignatureSignResponse.newBuilder().setSignature(ByteString.copyFrom(signatureValue)).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = SignatureSignResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Verifies a signature. */
  @Override
  public void verify(
      SignatureVerifyRequest request,
      StreamObserver<SignatureVerifyResponse> responseObserver) {
    SignatureVerifyResponse response;
    try {
      KeysetHandle publicKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getPublicKeyset().toByteArray()));
      PublicKeyVerify verifier = publicKeysetHandle.getPrimitive(PublicKeyVerify.class);
      verifier.verify(request.getSignature().toByteArray(), request.getData().toByteArray());
      response = SignatureVerifyResponse.getDefaultInstance();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = SignatureVerifyResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
