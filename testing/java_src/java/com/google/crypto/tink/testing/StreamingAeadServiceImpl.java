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

import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.StreamingAeadDecryptRequest;
import com.google.crypto.tink.testing.proto.StreamingAeadDecryptResponse;
import com.google.crypto.tink.testing.proto.StreamingAeadEncryptRequest;
import com.google.crypto.tink.testing.proto.StreamingAeadEncryptResponse;
import com.google.crypto.tink.testing.proto.StreamingAeadGrpc.StreamingAeadImplBase;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/** Implements a gRPC StreamingAead Testing service. */
public final class StreamingAeadServiceImpl extends StreamingAeadImplBase {

  public StreamingAeadServiceImpl() throws GeneralSecurityException {
  }

  @Override
  public void create(CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    Util.createPrimitiveForRpc(request, responseObserver, StreamingAead.class);
  }

  private StreamingAeadEncryptResponse encrypt(StreamingAeadEncryptRequest request)
      throws GeneralSecurityException {
    try {
      StreamingAead streamingAead =
          Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(StreamingAead.class);

      ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
      try (OutputStream encryptingStream =
          streamingAead.newEncryptingStream(
              ciphertextStream, request.getAssociatedData().toByteArray())) {
        request.getPlaintext().writeTo(encryptingStream);
      }
      return StreamingAeadEncryptResponse.newBuilder()
          .setCiphertext(ByteString.copyFrom(ciphertextStream.toByteArray()))
          .build();

    } catch (GeneralSecurityException e)  {
      return StreamingAeadEncryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      throw new GeneralSecurityException(e);
    }
  }

  @Override
  public void encrypt(
      StreamingAeadEncryptRequest request,
      StreamObserver<StreamingAeadEncryptResponse> responseObserver) {
    try {
      responseObserver.onNext(encrypt(request));
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }

  private StreamingAeadDecryptResponse decrypt(StreamingAeadDecryptRequest request)
      throws GeneralSecurityException {
    try {
      StreamingAead streamingAead =
          Util.parseBinaryProtoKeyset(request.getKeyset()).getPrimitive(StreamingAead.class);

      InputStream ciphertextStream = request.getCiphertext().newInput();
      InputStream decryptingStream = streamingAead.newDecryptingStream(
          ciphertextStream, request.getAssociatedData().toByteArray());
      ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();
      while (true) {
        int bytesRead = decryptingStream.read();
        if (bytesRead == -1) {
          break;
        }
        plaintextStream.write(bytesRead);
      }

      return StreamingAeadDecryptResponse.newBuilder().setPlaintext(
          ByteString.copyFrom(plaintextStream.toByteArray())).build();
    } catch (GeneralSecurityException | IOException e)  {
      return StreamingAeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void decrypt(
      StreamingAeadDecryptRequest request,
      StreamObserver<StreamingAeadDecryptResponse> responseObserver) {
    try {
      responseObserver.onNext(decrypt(request));
      responseObserver.onCompleted();
    } catch (GeneralSecurityException e) {
      responseObserver.onError(e);
    }
  }
}
