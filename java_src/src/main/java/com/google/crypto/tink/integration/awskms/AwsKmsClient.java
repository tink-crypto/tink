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

package com.google.crypto.tink.integration.awskms;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.PropertiesFileCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.google.auto.service.AutoService;
import com.google.common.base.Splitter;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * An implementation of {@link KmsClient} for <a href="https://aws.amazon.com/kms/">AWS KMS</a>.
 *
 * @since 1.0.0
 */
@AutoService(KmsClient.class)
public final class AwsKmsClient implements KmsClient {
  /** The prefix of all keys stored in AWS KMS. */
  public static final String PREFIX = "aws-kms://";

  @Nullable private AWSKMS awsKms;
  @Nullable private String keyUri;
  @Nullable private AWSCredentialsProvider provider;

  /**
   * Constructs a generic AwsKmsClient that is not bound to any specific key.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public AwsKmsClient() {}

  /**
   * Constructs a specific AwsKmsClient that is bound to a single key identified by {@code uri}.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public AwsKmsClient(String uri) {
    if (!uri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
  }

  /**
   * @return true either if this client is a generic one and uri starts with {@link
   *     AwsKmsClient#PREFIX}, or the client is a specific one that is bound to the key identified
   *     by {@code uri}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase(Locale.US).startsWith(PREFIX);
  }

  /**
   * Loads AWS credentials from a properties file.
   *
   * <p>The AWS access key ID is expected to be in the <code>accessKey</code> property and the AWS
   * secret key is expected to be in the <code>secretKey</code> property.
   *
   * @throws GeneralSecurityException if the client initialization fails
   */
  @Override
  @CanIgnoreReturnValue
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    try {
      if (credentialPath == null) {
        return withDefaultCredentials();
      }
      return withCredentialsProvider(new PropertiesFileCredentialsProvider(credentialPath));
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("cannot load credentials", e);
    }
  }

  /**
   * Loads default AWS credentials.
   *
   * <p>AWS credentials provider chain that looks for credentials in this order:
   *
   * <ul>
   *   <li>Environment Variables - AWS_ACCESS_KEY_ID and AWS_SECRET_KEY
   *   <li>Java System Properties - aws.accessKeyId and aws.secretKey
   *   <li>Credential profiles file at the default location (~/.aws/credentials)
   *   <li>Instance profile credentials delivered through the Amazon EC2 metadata service
   * </ul>
   *
   * @throws GeneralSecurityException if the client initialization fails
   */
  @Override
  @CanIgnoreReturnValue
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    try {
      return withCredentialsProvider(new DefaultAWSCredentialsProviderChain());
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("cannot load default credentials", e);
    }
  }

  /** Loads AWS credentials from a provider. */
  @CanIgnoreReturnValue
  public KmsClient withCredentialsProvider(AWSCredentialsProvider provider)
      throws GeneralSecurityException {
    this.provider = provider;
    return this;
  }

  /**
   * Specifies the {@link com.amazonaws.services.kms.AWSKMS} object to be used. Only used for
   * testing.
   */
  @CanIgnoreReturnValue
  KmsClient withAwsKms(@Nullable AWSKMS awsKms) {
    this.awsKms = awsKms;
    return this;
  }

  private static String removePrefix(String expectedPrefix, String kmsKeyUri) {
    if (!kmsKeyUri.toLowerCase(Locale.US).startsWith(expectedPrefix)) {
      throw new IllegalArgumentException(
          String.format("key URI must start with %s", expectedPrefix));
    }
    return kmsKeyUri.substring(expectedPrefix.length());
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }

    try {
      String keyId = removePrefix(PREFIX, uri);
      AWSKMS client = awsKms;
      List<String> tokens = Splitter.on(':').splitToList(keyId);
      if (tokens.size() < 4) {
        throw new IllegalArgumentException("invalid key URI");
      }
      String regionName = tokens.get(3);
      if (client == null) {
        client =
            AWSKMSClientBuilder.standard()
                .withCredentials(provider)
                .withRegion(Regions.fromName(regionName))
                .build();
      }
      return new AwsKmsAead(client, keyId);
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("cannot load credentials from provider", e);
    }
  }

  /**
   * Creates and registers a {@link #AwsKmsClient} with the Tink runtime.
   *
   * <p>If {@code keyUri} is present, it is the only key that the new client will support. Otherwise
   * the new client supports all AWS KMS keys.
   *
   * <p>If {@code credentialPath} is present, load the credentials from that. Otherwise use the
   * default credentials.
   */
  public static void register(Optional<String> keyUri, Optional<String> credentialPath)
      throws GeneralSecurityException {
    registerWithAwsKms(keyUri, credentialPath, null);
  }

  /**
   * Does the same as {@link #register}, but with an additional {@code awsKms} argument. Only used
   * for testing.
   */
  static void registerWithAwsKms(
      Optional<String> keyUri, Optional<String> credentialPath, @Nullable AWSKMS awsKms)
      throws GeneralSecurityException {
    AwsKmsClient client;
    if (keyUri.isPresent()) {
      client = new AwsKmsClient(keyUri.get());
    } else {
      client = new AwsKmsClient();
    }
    if (credentialPath.isPresent()) {
      client.withCredentials(credentialPath.get());
    } else {
      client.withDefaultCredentials();
    }
    client.withAwsKms(awsKms);
    KmsClients.add(client);
  }
}
