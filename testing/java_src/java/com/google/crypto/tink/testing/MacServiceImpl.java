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
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.testing.proto.ComputeMacRequest;
import com.google.crypto.tink.testing.proto.ComputeMacResponse;
import com.google.crypto.tink.testing.proto.MacGrpc.MacImplBase;
import com.google.crypto.tink.testing.proto.VerifyMacRequest;
import com.google.crypto.tink.testing.proto.VerifyMacResponse;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implements a gRPC MAC Testing service. */
public final class MacServiceImpl extends MacImplBase {

  public MacServiceImpl() throws GeneralSecurityException {
  }

  /** Encrypts a message. */
  @Override
  public void computeMac(
      ComputeMacRequest request,
      StreamObserver<ComputeMacResponse> responseObserver) {
    ComputeMacResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Mac mac = keysetHandle.getPrimitive(Mac.class);
      byte[] macValue = mac.computeMac(request.getData().toByteArray());
      response = ComputeMacResponse.newBuilder().setMacValue(ByteString.copyFrom(macValue)).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = ComputeMacResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Decrypts a message. */
  @Override
  public void verifyMac(
      VerifyMacRequest request,
      StreamObserver<VerifyMacResponse> responseObserver) {
    VerifyMacResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Mac mac = keysetHandle.getPrimitive(Mac.class);
      mac.verifyMac(request.getMacValue().toByteArray(), request.getData().toByteArray());
      response = VerifyMacResponse.getDefaultInstance();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = VerifyMacResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
