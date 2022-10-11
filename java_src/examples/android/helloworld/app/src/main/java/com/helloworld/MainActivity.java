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

package com.helloworld;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** This activity allows users to encrypt and decrypt a string. */
public class MainActivity extends AppCompatActivity {
  private TinkApplication mApplication;
  private EditText mPlaintextView;
  private EditText mAssociatedDataView;
  private EditText mCiphertextView;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    mApplication = (TinkApplication) getApplicationContext();

    mPlaintextView = (EditText) findViewById(R.id.plaintext);
    mAssociatedDataView = (EditText) findViewById(R.id.associated_data);
    mCiphertextView = (EditText) findViewById(R.id.ciphertext);
    Button mEncryptButton = (Button) findViewById(R.id.encrypt_button);
    mEncryptButton.setOnClickListener(
        new OnClickListener() {
          @Override
          public void onClick(View view) {
            attemptEncrypt();
          }
        });
    Button mDecryptButton = (Button) findViewById(R.id.decrypt_button);
    mDecryptButton.setOnClickListener(
        new OnClickListener() {
          @Override
          public void onClick(View view) {
            attemptDecrypt();
          }
        });
  }

  private void attemptEncrypt() {
    mPlaintextView.setError(null);
    mCiphertextView.setError(null);
    mCiphertextView.setText("");

    try {
      byte[] plaintext = mPlaintextView.getText().toString().getBytes(StandardCharsets.UTF_8);
      // An artifical step to test whether Tink can co-exist with protobuf-lite.
      ByteString pStr = ByteString.copyFrom(plaintext);
      byte[] associatedData =
          mAssociatedDataView.getText().toString().getBytes(StandardCharsets.UTF_8);
      byte[] ciphertext = mApplication.aead.encrypt(pStr.toByteArray(), associatedData);
      mCiphertextView.setText(base64Encode(ciphertext));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      mCiphertextView.setError(
          String.format("%s: %s", getString(R.string.error_cannot_encrypt), e.toString()));
      mPlaintextView.requestFocus();
    }
  }

  private void attemptDecrypt() {
    mPlaintextView.setError(null);
    mPlaintextView.setText("");
    mCiphertextView.setError(null);

    try {
      byte[] ciphertext = base64Decode(mCiphertextView.getText().toString());
      byte[] associatedData =
          mAssociatedDataView.getText().toString().getBytes(StandardCharsets.UTF_8);
      byte[] plaintext = mApplication.aead.decrypt(ciphertext, associatedData);
      mPlaintextView.setText(new String(plaintext, StandardCharsets.UTF_8));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      mPlaintextView.setError(
          String.format("%s: %s", getString(R.string.error_cannot_decrypt), e.toString()));
      mCiphertextView.requestFocus();
    }
  }

  private static String base64Encode(final byte[] input) {
    return Base64.encodeToString(input, Base64.DEFAULT);
  }

  private static byte[] base64Decode(String input) {
    return Base64.decode(input, Base64.DEFAULT);
  }
}
