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

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.testing.proto.ComputeMacRequest;
import com.google.crypto.tink.testing.proto.ComputeMacResponse;
import com.google.crypto.tink.testing.proto.MacGrpc.MacImplBase;
import com.google.crypto.tink.testing.proto.VerifyMacRequest;
import com.google.crypto.tink.testing.proto.VerifyMacResponse;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/** Implements a gRPC MAC Testing service. */
public final class MacServiceImpl extends MacImplBase {

  public MacServiceImpl() throws GeneralSecurityException {
  }

  private ComputeMacResponse computeMac(
      ComputeMacRequest request) throws GeneralSecurityException {
    try {
      Mac mac = Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(Mac.class);
      byte[] macValue = mac.computeMac(request.getData().toByteArray());
      return ComputeMacResponse.newBuilder().setMacValue(ByteString.copyFrom(macValue)).build();
    } catch (GeneralSecurityException e)  {
      return ComputeMacResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void computeMac(
      ComputeMacRequest request,
      StreamObserver<ComputeMacResponse> responseObserver) {
    try {
      responseObserver.onNext(computeMac(request));
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }

  private VerifyMacResponse verifyMac(VerifyMacRequest request) throws GeneralSecurityException {
    try {
      Mac mac = Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(Mac.class);
      mac.verifyMac(request.getMacValue().toByteArray(), request.getData().toByteArray());
      return VerifyMacResponse.getDefaultInstance();
    } catch (GeneralSecurityException e) {
      return VerifyMacResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void verifyMac(
      VerifyMacRequest request,
      StreamObserver<VerifyMacResponse> responseObserver) {
    try {
      responseObserver.onNext(verifyMac(request));
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }
}
