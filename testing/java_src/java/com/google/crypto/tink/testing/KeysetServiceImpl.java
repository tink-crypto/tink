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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.testing.proto.KeysetFromJsonRequest;
import com.google.crypto.tink.testing.proto.KeysetFromJsonResponse;
import com.google.crypto.tink.testing.proto.KeysetGenerateRequest;
import com.google.crypto.tink.testing.proto.KeysetGenerateResponse;
import com.google.crypto.tink.testing.proto.KeysetGrpc.KeysetImplBase;
import com.google.crypto.tink.testing.proto.KeysetPublicRequest;
import com.google.crypto.tink.testing.proto.KeysetPublicResponse;
import com.google.crypto.tink.testing.proto.KeysetReadEncryptedRequest;
import com.google.crypto.tink.testing.proto.KeysetReadEncryptedResponse;
import com.google.crypto.tink.testing.proto.KeysetReaderType;
import com.google.crypto.tink.testing.proto.KeysetTemplateRequest;
import com.google.crypto.tink.testing.proto.KeysetTemplateResponse;
import com.google.crypto.tink.testing.proto.KeysetToJsonRequest;
import com.google.crypto.tink.testing.proto.KeysetToJsonResponse;
import com.google.crypto.tink.testing.proto.KeysetWriteEncryptedRequest;
import com.google.crypto.tink.testing.proto.KeysetWriteEncryptedResponse;
import com.google.crypto.tink.testing.proto.KeysetWriterType;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
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
      byte[] serializedPublicKeyset =
          TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
      response =
          KeysetGenerateResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(serializedPublicKeyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetGenerateResponse.newBuilder().setErr(e.toString()).build();
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
          TinkProtoKeysetFormat.parseKeyset(
              request.getPrivateKeyset().toByteArray(), InsecureSecretKeyAccess.get());
      KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
      byte[] serializedPublicKeyset =
          TinkProtoKeysetFormat.serializeKeyset(publicKeysetHandle, InsecureSecretKeyAccess.get());
      response =
          KeysetPublicResponse.newBuilder()
              .setPublicKeyset(ByteString.copyFrom(serializedPublicKeyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetPublicResponse.newBuilder().setErr(e.toString()).build();
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
          TinkProtoKeysetFormat.parseKeyset(
              request.getKeyset().toByteArray(), InsecureSecretKeyAccess.get());
      String jsonKeyset =
          TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
      response = KeysetToJsonResponse.newBuilder().setJsonKeyset(jsonKeyset).build();
    } catch (GeneralSecurityException e) {
      response = KeysetToJsonResponse.newBuilder().setErr(e.toString()).build();
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
          TinkJsonProtoKeysetFormat.parseKeyset(
              request.getJsonKeyset(), InsecureSecretKeyAccess.get());
      byte[] serializeKeyset =
          TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
      response =
          KeysetFromJsonResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(serializeKeyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetFromJsonResponse.newBuilder().setErr(e.toString()).build();
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
          TinkProtoKeysetFormat.parseKeyset(
              request.getMasterKeyset().toByteArray(), InsecureSecretKeyAccess.get());
      Aead masterAead = masterKeysetHandle.getPrimitive(Aead.class);

      // read encrypted keyset to keysetHandle
      byte[] associatedData = request.getAssociatedData().getValue().toByteArray();

      KeysetHandle keysetHandle;
      if (request.getKeysetReaderType() == KeysetReaderType.KEYSET_READER_BINARY) {
        keysetHandle =
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                request.getEncryptedKeyset().toByteArray(), masterAead, associatedData);
      } else if (request.getKeysetReaderType() == KeysetReaderType.KEYSET_READER_JSON) {
        keysetHandle =
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                request.getEncryptedKeyset().toStringUtf8(), masterAead, associatedData);
      } else {
        throw new IllegalArgumentException("unknown keyset reader type");
      }

      // get keyset from keysetHandle
      byte[] keyset =
          TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
      response =
          KeysetReadEncryptedResponse.newBuilder().setKeyset(ByteString.copyFrom(keyset)).build();
    } catch (GeneralSecurityException e) {
      response = KeysetReadEncryptedResponse.newBuilder().setErr(e.toString()).build();
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
          TinkProtoKeysetFormat.parseKeyset(
              request.getMasterKeyset().toByteArray(), InsecureSecretKeyAccess.get());
      Aead masterAead = masterKeysetHandle.getPrimitive(Aead.class);

      // get keysetHandle
      KeysetHandle keysetHandle =
          TinkProtoKeysetFormat.parseKeyset(
              request.getKeyset().toByteArray(), InsecureSecretKeyAccess.get());

      // write keysetHandle as encrypted keyset
      byte[] associatedData = request.getAssociatedData().getValue().toByteArray();
      byte[] keyset;
      if (request.getKeysetWriterType() == KeysetWriterType.KEYSET_WRITER_BINARY) {
        keyset =
            TinkProtoKeysetFormat.serializeEncryptedKeyset(
                keysetHandle, masterAead, associatedData);
      } else if (request.getKeysetWriterType() == KeysetWriterType.KEYSET_WRITER_JSON) {
        keyset =
            TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
                    keysetHandle, masterAead, associatedData)
                .getBytes(UTF_8);
      } else {
        throw new IllegalArgumentException("unknown keyset writer type");
      }
      response =
          KeysetWriteEncryptedResponse.newBuilder()
              .setEncryptedKeyset(ByteString.copyFrom(keyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetWriteEncryptedResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
