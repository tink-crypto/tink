// Copyright 2022 Google LLC
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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.testing.proto.AnnotatedKeyset;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/**
 * Utility functions for implementing Services.
 */
final class Util {
  static KeysetHandle parseBinaryProtoKeyset(AnnotatedKeyset annotatedKeyset)
      throws GeneralSecurityException {
    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(
            annotatedKeyset.getSerializedKeyset().toByteArray(), InsecureSecretKeyAccess.get());
    return KeysetHandle.newBuilder(handle)
        .setMonitoringAnnotations(
            MonitoringAnnotations.newBuilder().addAll(annotatedKeyset.getAnnotationsMap()).build())
        .build();
  }

  /** Responds to a "create" request for a specific class */
  static void createPrimitiveForRpc(
      CreationRequest request,
      StreamObserver<CreationResponse> responseObserver,
      Class<?> primitiveClass) {
    try {
      KeysetHandle keysetHandle = parseBinaryProtoKeyset(request.getAnnotatedKeyset());
      // We create to check if there is an exception thrown.
      Object unused = keysetHandle.getPrimitive(primitiveClass);
    } catch (GeneralSecurityException e) {
      responseObserver.onNext(CreationResponse.newBuilder().setErr(e.toString()).build());
      responseObserver.onCompleted();
      return;
    }
    responseObserver.onNext(CreationResponse.getDefaultInstance());
    responseObserver.onCompleted();
  }

  private Util() {}
}
