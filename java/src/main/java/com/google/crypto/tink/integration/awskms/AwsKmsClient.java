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
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.google.auto.service.AutoService;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.subtle.Validators;
import java.security.GeneralSecurityException;

/**
 * An implementation of {@link KmsClient} for <a href="https://aws.amazon.com/kms/">AWS KMS</a>.
 *
 * @since 1.0.0
 */
@AutoService(KmsClient.class)
public final class AwsKmsClient implements KmsClient {
  /** The prefix of all keys stored in AWS KMS. */
  public static final String PREFIX = "aws-kms://";

  private AWSKMS client;
  private String keyUri;

  /** Constructs a generic AwsKmsClient that is not bound to any specific key. */
  public AwsKmsClient() {}

  /** Constructs a specific AwsKmsClient that is bound to a single key identified by {@code uri}. */
  public AwsKmsClient(String uri) {
    if (!uri.toLowerCase().startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
  }

  /**
   * @return @return true either if this client is a generic one and uri starts with {@link
   *     AwsKmsClient#PREFIX}, or the client is a specific one that is bound to the key identified
   *     by {@code uri}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase().startsWith(PREFIX);
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
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    try {
      return withCredentialsProvider(new DefaultAWSCredentialsProviderChain());
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("cannot load default credentials", e);
    }
  }

  /** Loads AWS credentials from a provider. */
  private KmsClient withCredentialsProvider(AWSCredentialsProvider provider)
      throws GeneralSecurityException {
    try {
      this.client = AWSKMSClientBuilder.standard().withCredentials(provider).build();
      return this;
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("cannot load credentials from provider", e);
    }
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format("this client is bound to %s, cannot load keys bound to %s",
              this.keyUri, uri));
    }
    return new AwsKmsAead(client, Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri));
  }
}
