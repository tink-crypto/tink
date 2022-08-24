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

import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSet;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.PrfSetComputeRequest;
import com.google.crypto.tink.testing.proto.PrfSetComputeResponse;
import com.google.crypto.tink.testing.proto.PrfSetGrpc.PrfSetImplBase;
import com.google.crypto.tink.testing.proto.PrfSetKeyIdsRequest;
import com.google.crypto.tink.testing.proto.PrfSetKeyIdsResponse;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;
import java.util.Map;

/** Implements a gRPC Aead Testing service. */
public final class PrfSetServiceImpl extends PrfSetImplBase {

  public PrfSetServiceImpl() throws GeneralSecurityException {
  }

  @Override
  public void create(CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    Util.createPrimitiveForRpc(request, responseObserver, PrfSet.class);
  }

  private PrfSetKeyIdsResponse keyIds(
      PrfSetKeyIdsRequest request) throws GeneralSecurityException {
    try {
      PrfSet prfSet = Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(PrfSet.class);
      PrfSetKeyIdsResponse.Output output = PrfSetKeyIdsResponse.Output.newBuilder()
          .setPrimaryKeyId(prfSet.getPrimaryId())
          .addAllKeyId(prfSet.getPrfs().keySet())
          .build();
      return PrfSetKeyIdsResponse.newBuilder().setOutput(output).build();
    } catch (GeneralSecurityException e)  {
      return PrfSetKeyIdsResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void keyIds(
      PrfSetKeyIdsRequest request,
      StreamObserver<PrfSetKeyIdsResponse> responseObserver) {
    try {
      responseObserver.onNext(keyIds(request));
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }

  /** Computes the output of one PRF. */
  private PrfSetComputeResponse compute(PrfSetComputeRequest request)
      throws GeneralSecurityException {
    try {
      PrfSet prfSet = Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(PrfSet.class);
      Map<Integer, Prf> prfs = prfSet.getPrfs();
      if (!prfs.containsKey(request.getKeyId())) {
        return PrfSetComputeResponse.newBuilder().setErr("Unknown Key ID.").build();
      } else {
        byte[] output =
            prfs.get(request.getKeyId())
                .compute(request.getInputData().toByteArray(), request.getOutputLength());
        return
            PrfSetComputeResponse.newBuilder().setOutput(ByteString.copyFrom(output)).build();
      }
    } catch (GeneralSecurityException e) {
      return PrfSetComputeResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void compute(
      PrfSetComputeRequest request,
      StreamObserver<PrfSetComputeResponse> responseObserver) {
    try {
      responseObserver.onNext(compute(request));
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }
}
