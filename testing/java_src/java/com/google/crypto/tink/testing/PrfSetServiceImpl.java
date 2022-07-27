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
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.testing.proto.PrfSetComputeRequest;
import com.google.crypto.tink.testing.proto.PrfSetComputeResponse;
import com.google.crypto.tink.testing.proto.PrfSetGrpc.PrfSetImplBase;
import com.google.crypto.tink.testing.proto.PrfSetKeyIdsRequest;
import com.google.crypto.tink.testing.proto.PrfSetKeyIdsResponse;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

/** Implements a gRPC Aead Testing service. */
public final class PrfSetServiceImpl extends PrfSetImplBase {

  public PrfSetServiceImpl() throws GeneralSecurityException {
  }

  /** Returns the key IDs of the keyset. */
  @Override
  public void keyIds(
      PrfSetKeyIdsRequest request, StreamObserver<PrfSetKeyIdsResponse> responseObserver) {
    PrfSetKeyIdsResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      PrfSet prfSet = keysetHandle.getPrimitive(PrfSet.class);
      PrfSetKeyIdsResponse.Output output = PrfSetKeyIdsResponse.Output.newBuilder()
          .setPrimaryKeyId(prfSet.getPrimaryId())
          .addAllKeyId(prfSet.getPrfs().keySet())
          .build();
      response =
          PrfSetKeyIdsResponse.newBuilder()
          .setOutput(output)
          .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = PrfSetKeyIdsResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  /** Computes the output of one PRF. */
  @Override
  public void compute(
      PrfSetComputeRequest request, StreamObserver<PrfSetComputeResponse> responseObserver) {
    PrfSetComputeResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      PrfSet prfSet = keysetHandle.getPrimitive(PrfSet.class);
      Map<Integer, Prf> prfs = prfSet.getPrfs();
      if (!prfs.containsKey(request.getKeyId())) {
        response = PrfSetComputeResponse.newBuilder().setErr("Unknown Key ID.").build();
      } else {
        byte[] output =
            prfs.get(request.getKeyId())
                .compute(request.getInputData().toByteArray(), request.getOutputLength());
        response =
            PrfSetComputeResponse.newBuilder().setOutput(ByteString.copyFrom(output)).build();
      }
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = PrfSetComputeResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
