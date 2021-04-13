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
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.proto.testing.StreamingAeadDecryptRequest;
import com.google.crypto.tink.proto.testing.StreamingAeadDecryptResponse;
import com.google.crypto.tink.proto.testing.StreamingAeadEncryptRequest;
import com.google.crypto.tink.proto.testing.StreamingAeadEncryptResponse;
import com.google.crypto.tink.proto.testing.StreamingAeadGrpc.StreamingAeadImplBase;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
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

  /** Encrypts a message. */
  @Override
  public void encrypt(
      StreamingAeadEncryptRequest request,
      StreamObserver<StreamingAeadEncryptResponse> responseObserver) {
    StreamingAeadEncryptResponse response;
    try {
      KeysetHandle keysetHandle = CleartextKeysetHandle.read(
          BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

      ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
      try (OutputStream encryptingStream =
          streamingAead.newEncryptingStream(
              ciphertextStream, request.getAssociatedData().toByteArray())) {
        request.getPlaintext().writeTo(encryptingStream);
      }
      response =
          StreamingAeadEncryptResponse.newBuilder()
              .setCiphertext(ByteString.copyFrom(ciphertextStream.toByteArray()))
              .build();

    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = StreamingAeadEncryptResponse.newBuilder().setErr(e.toString()).build();
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
      StreamingAeadDecryptRequest request,
      StreamObserver<StreamingAeadDecryptResponse> responseObserver) {
    StreamingAeadDecryptResponse response;
    try {
      KeysetHandle keysetHandle = CleartextKeysetHandle.read(
          BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

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

      response = StreamingAeadDecryptResponse.newBuilder().setPlaintext(
          ByteString.copyFrom(plaintextStream.toByteArray())).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = StreamingAeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      response = StreamingAeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
