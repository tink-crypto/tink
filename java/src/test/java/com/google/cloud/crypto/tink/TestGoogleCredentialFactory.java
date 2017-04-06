// Copyright 2017 Google Inc.
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

package com.google.cloud.crypto.tink;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.aead.GoogleCredentialFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Produces {@code GoogleCredential} used in tests.
 */
public class TestGoogleCredentialFactory implements GoogleCredentialFactory {
  // This key is restricted to the service account created by {@code createGoogleCredential}.
  public static final String RESTRICTED = TestUtil.createGoogleCloudKmsKeyUri(
      "testing-cloud-kms-159306", "global", "tink_unit_tests", "restricted");

  /**
   * Depending on {@code key}, produces either a default credential or a hardcoded one.
   */
  @Override
  public GoogleCredential getCredential(GoogleCloudKmsAeadKey key) throws IOException {
    GoogleCredential cred;
    if (key.getKmsKeyUri().equals(RESTRICTED)) {
      cred = createGoogleCredential();
    } else {
      cred = GoogleCredential.getApplicationDefault();
    }
    // Depending on the environment that provides the default credentials (e.g. Compute Engine, App
    // Engine), the credentials may require us to specify the scopes we need explicitly.
    // Check for this case, and inject the scope if required.
    if (cred.createScopedRequired()) {
      cred = cred.createScoped(CloudKMSScopes.all());
    }
    return cred;
  }

  /**
   * Hardcoded credential that is granted access to the {@code RESTRICTED} key.
   */
  public static GoogleCredential createGoogleCredential() throws IOException {
    String serviceAccount = "{\n"
        + "\"type\": \"service_account\",\n"
        + "\"project_id\": \"testing-cloud-kms-159306\",\n"
        + "\"private_key_id\": \"bb7cdcb4f2058987bc6b43df46e3b8988bb6219c\",\n"
        + "\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n"
        + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDGgxJrujJjzqa5\\n"
        + "6KT239WwMuuFQZ99OxvPcv5PWQEH6dAb3lx8Lm+W3C/r1q8JK+M1OrSPGhjjMWSA\\n"
        + "2kto9itQpVVF75jej8GYjblDIsky4tY0aPb6AOt0hH20fF8STT+o4qSXrzNSgA+T\\n"
        + "hQ6LOLySzbzDcOFaoau9f5+eblgW3Z12YtS3UCPkmkSJWhoM4kyRCm4Ld8Kj0tnI\\n"
        + "RaHw4dduLipalA1R0jLIiN92d0OYX9Krh8UDiqLwO4IMD69KyDaTOv7vCVzAF9qV\\n"
        + "+up/jbuY5J+wsrTdQRZu3KdtK/0PHCsqTkyXffJ4yeybCOg2hcxTGLLOV3Bg0shw\\n"
        + "t46TRGynAgMBAAECggEAFI1DXfXT+7NMXZjxY0G/PNO4wH4PxgZVlb+hBpP/YFNb\\n"
        + "oVb/Gjgwg1zedTsvufJaPouKX/piszrM3e47um0qBNppHql0mS4m6+VYVdQHIoaL\\n"
        + "iLeJQk7QEasZ3JK3wQxQV+rHAZE47gSmGC7BV7aTB1vXfCB2pExynFbXLq7b3dn7\\n"
        + "BlSnpH5SXTAqjo/kdOHio8bV8SuON4WA9ag2OkZaCT7FnJ8lgtT/PnQ92OUw6NIx\\n"
        + "b1hyNZtelUKMoaLUeR5rjKa/PxMnQiKab0Ai8luyWdEGl/GCwe/uqGOaCxkEaOPf\\n"
        + "gflz84FEfj7VjnwmZisFC0juVdlK41uptlAWu/ZGwQKBgQDxiUEflyc55+p7Tz1R\\n"
        + "nfN5+4dwAdAGiK5q4dPOUFKP1Q8cUdO3ZzF+cS7aoxSTszDd1TWy+w5uvX2hLodW\\n"
        + "Pq86c2rvYQcBxE53fyhALBosvdUB9GYs4fco0QRHOujPg6aw5J+K5nqiHmflT448\\n"
        + "ulCfkD88irdc9ZnOSGez1nQYxwKBgQDSZkILG3uMeN/wg7UPyjCHcCQJKv1xgqWk\\n"
        + "K1VrjHce3VhMDETz2zbxj3naEngWaHF3GXwoEM09y7H/WC0mTUywGFS5bFa1L47O\\n"
        + "492P278kjNT3wtwugZUj0qhnfVfpEVpfTQD5RQ7vVEIdu3lHOUvOFZfJsbLWdbqA\\n"
        + "qrce1rvtIQKBgFBRZP99QwUFcrq4edqHHKzGkJ4VbDiQAPf3yngDy8Cah+DR8QY+\\n"
        + "4X17Y6o+qpwG7UwHF0lCJOV8S6dqkoSCacCVGs0pRaw3vCQOe7MDN10Dby6sN8Hb\\n"
        + "DlZbUwHgvAQtciPGkqscw1DfrYrabqERD7hPvkeClUDrRs8K0rlBqe+HAoGAXvXO\\n"
        + "OwslYQoxMHGRZ9X+vzIq4YRorTGlJwpz3D2iieim8HPdLx6ylqYF/hm13482HuX+\\n"
        + "tmqW55wm8zNN9WqQAS6KFsJCBDa5wsDvf/1TMODrQgPNsqPDt05duY/F/KhbXIX5\\n"
        + "uYekrPofeSHjI/VFNHdkcaDlMYwjJ+1lBuMuIGECgYAfpEWSshkwfUtDQKAEzh+K\\n"
        + "9314QfSrEBFrr47qAf2Qf0/lH9VvB/OaZK+04dgjWolNTedueS/OYbtT9KFxfa/I\\n"
        + "tmT8a9lXHXRvLOEYq9uttZuRPeTCQ2bpMsSmMmEYwllJRMI5sgOrkzmrx6/Zs+xl\\n"
        + "IYBLXRxQ6kzoWDGx+ZpuZQ==\\n"
        + "-----END PRIVATE KEY-----\\n"
        + "\",\n"
        + "\"client_email\": "
        + "\"tink-unit-tests@testing-cloud-kms-159306.iam.gserviceaccount.com\",\n"
        + "\"client_id\": \"109010856886823037140\",\n"
        + "\"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n"
        + "\"token_uri\": \"https://accounts.google.com/o/oauth2/token\",\n"
        + "\"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n"
        + "\"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/"
        + "tink-unit-tests%40testing-cloud-kms-159306.iam.gserviceaccount.com\"\n"
        + "}";
    return GoogleCredential.fromStream(
        new ByteArrayInputStream(serviceAccount.getBytes(StandardCharsets.UTF_8)));
  }
}