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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.testing.KeysetFromJsonRequest;
import com.google.crypto.tink.proto.testing.KeysetFromJsonResponse;
import com.google.crypto.tink.proto.testing.KeysetGenerateRequest;
import com.google.crypto.tink.proto.testing.KeysetGenerateResponse;
import com.google.crypto.tink.proto.testing.KeysetGrpc.KeysetImplBase;
import com.google.crypto.tink.proto.testing.KeysetPublicRequest;
import com.google.crypto.tink.proto.testing.KeysetPublicResponse;
import com.google.crypto.tink.proto.testing.KeysetReadEncryptedRequest;
import com.google.crypto.tink.proto.testing.KeysetReadEncryptedResponse;
import com.google.crypto.tink.proto.testing.KeysetTemplateRequest;
import com.google.crypto.tink.proto.testing.KeysetTemplateResponse;
import com.google.crypto.tink.proto.testing.KeysetToJsonRequest;
import com.google.crypto.tink.proto.testing.KeysetToJsonResponse;
import com.google.crypto.tink.proto.testing.KeysetWriteEncryptedRequest;
import com.google.crypto.tink.proto.testing.KeysetWriteEncryptedResponse;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Implement a gRPC Keyset Testing service. */
public final class KeysetServiceImpl extends KeysetImplBase {

  public KeysetServiceImpl() throws GeneralSecurityException {
  }

  @Override
  public void getTemplate(
      KeysetTemplateRequest request, StreamObserver<KeysetTemplateResponse> responseObserver) {
    KeysetTemplateResponse response;
    try {
      KeyTemplate template = KeyTemplates.get(request.getTemplateName());
      response =
          KeysetTemplateResponse.newBuilder()
              .setKeyTemplate(ByteString.copyFrom(KeyTemplateProtoConverter.toByteArray(template)))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetTemplateResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  @Override
  public void generate(
      KeysetGenerateRequest request, StreamObserver<KeysetGenerateResponse> responseObserver) {
    KeysetGenerateResponse response;
    try {
      KeyTemplate template =
          KeyTemplateProtoConverter.fromByteArray(request.getTemplate().toByteArray());
      KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
      Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
      ByteArrayOutputStream keysetStream = new ByteArrayOutputStream();
      BinaryKeysetWriter.withOutputStream(keysetStream).write(keyset);
      keysetStream.close();
      response =
          KeysetGenerateResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(keysetStream.toByteArray()))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetGenerateResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  @Override
  public void public_(
      KeysetPublicRequest request, StreamObserver<KeysetPublicResponse> responseObserver) {
    KeysetPublicResponse response;
    try {
      KeysetHandle privateKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getPrivateKeyset().toByteArray()));
      KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
      Keyset publicKeyset = CleartextKeysetHandle.getKeyset(publicKeysetHandle);
      ByteArrayOutputStream publicKeysetStream = new ByteArrayOutputStream();
      BinaryKeysetWriter.withOutputStream(publicKeysetStream).write(publicKeyset);
      publicKeysetStream.close();
      response =
          KeysetPublicResponse.newBuilder()
              .setPublicKeyset(ByteString.copyFrom(publicKeysetStream.toByteArray()))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e)  {
      response = KeysetPublicResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  @Override
  public void toJson(
      KeysetToJsonRequest request, StreamObserver<KeysetToJsonResponse> responseObserver) {
    KeysetToJsonResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));
      Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
      ByteArrayOutputStream jsonKeysetStream = new ByteArrayOutputStream();
      JsonKeysetWriter.withOutputStream(jsonKeysetStream).write(keyset);
      jsonKeysetStream.close();
      response =
          KeysetToJsonResponse.newBuilder().setJsonKeyset(jsonKeysetStream.toString("UTF-8")).build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = KeysetToJsonResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  @Override
  public void fromJson(
      KeysetFromJsonRequest request, StreamObserver<KeysetFromJsonResponse> responseObserver) {
    KeysetFromJsonResponse response;
    try {
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(JsonKeysetReader.withString(request.getJsonKeyset()));
      Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
      ByteArrayOutputStream keysetStream = new ByteArrayOutputStream();
      BinaryKeysetWriter.withOutputStream(keysetStream).write(keyset);
      keysetStream.close();
      response =
          KeysetFromJsonResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(keysetStream.toByteArray()))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = KeysetFromJsonResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  @Override
  public void readEncrypted(
      KeysetReadEncryptedRequest request,
      StreamObserver<KeysetReadEncryptedResponse> responseObserver) {
    KeysetReadEncryptedResponse response;
    try {
      // get masterAead
      KeysetHandle masterKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getMasterKeyset().toByteArray()));
      Aead masterAead = masterKeysetHandle.getPrimitive(Aead.class);

      // read encrypted keyset to keysetHandle
      KeysetReader reader =
          BinaryKeysetReader.withBytes(request.getEncryptedKeyset().toByteArray());
      KeysetHandle keysetHandle;
      if (request.hasAssociatedData()) {
        keysetHandle =
            KeysetHandle.readWithAssociatedData(
                reader, masterAead, request.getAssociatedData().getValue().toByteArray());
      } else {
        keysetHandle = KeysetHandle.read(reader, masterAead);
      }

      // get keyset from keysetHandle
      Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
      ByteArrayOutputStream keysetStream = new ByteArrayOutputStream();
      BinaryKeysetWriter.withOutputStream(keysetStream).write(keyset);
      keysetStream.close();
      response =
          KeysetReadEncryptedResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(keysetStream.toByteArray()))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = KeysetReadEncryptedResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  @Override
  public void writeEncrypted(
      KeysetWriteEncryptedRequest request,
      StreamObserver<KeysetWriteEncryptedResponse> responseObserver) {
    KeysetWriteEncryptedResponse response;
    try {
      // get masterAead
      KeysetHandle masterKeysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getMasterKeyset().toByteArray()));
      Aead masterAead = masterKeysetHandle.getPrimitive(Aead.class);

      // get keysetHandle
      KeysetHandle keysetHandle =
          CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(request.getKeyset().toByteArray()));

      // write keysetHandle as encrypted keyset
      ByteArrayOutputStream keysetStream = new ByteArrayOutputStream();
      KeysetWriter writer = BinaryKeysetWriter.withOutputStream(keysetStream);
      if (request.hasAssociatedData()) {
        keysetHandle.writeWithAssociatedData(
            writer, masterAead, request.getAssociatedData().getValue().toByteArray());
      } else {
        keysetHandle.write(writer, masterAead);
      }

      keysetStream.close();
      response =
          KeysetWriteEncryptedResponse.newBuilder()
              .setEncryptedKeyset(ByteString.copyFrom(keysetStream.toByteArray()))
              .build();
    } catch (GeneralSecurityException | InvalidProtocolBufferException e) {
      response = KeysetWriteEncryptedResponse.newBuilder().setErr(e.toString()).build();
    } catch (IOException e) {
      responseObserver.onError(Status.UNKNOWN.withDescription(e.getMessage()).asException());
      return;
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
