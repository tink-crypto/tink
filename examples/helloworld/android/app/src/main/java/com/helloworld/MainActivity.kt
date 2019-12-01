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
package com.helloworld

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException

/**
 * This activity allows users to encrypt and decrypt a string.
 */
class MainActivity : AppCompatActivity() {

    private var mApplication: TinkApplication? = null
    private var mPlaintextView: EditText? = null
    private var mCiphertextView: EditText? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        mApplication = applicationContext as TinkApplication
        mPlaintextView = findViewById<View>(R.id.plaintext) as EditText
        mCiphertextView = findViewById<View>(R.id.ciphertext) as EditText
        val mEncryptButton =
            findViewById<View>(R.id.encrypt_button) as Button
        mEncryptButton.setOnClickListener { attemptEncrypt() }
        val mDecryptButton =
            findViewById<View>(R.id.decrypt_button) as Button
        mDecryptButton.setOnClickListener { attemptDecrypt() }
    }

    private fun attemptEncrypt() {
        mPlaintextView?.error = null
        mCiphertextView?.error = null
        mCiphertextView?.setText("")
        try {
            val plaintext = mPlaintextView?.text.toString()
                .toByteArray(StandardCharsets.UTF_8)
            val ciphertext =
                mApplication?.aead?.encrypt(plaintext, EMPTY_ASSOCIATED_DATA)
            mCiphertextView?.setText(base64Encode(ciphertext!!))
        } catch (e: GeneralSecurityException) {
            mCiphertextView?.error = String.format(
                "%s: %s",
                getString(R.string.error_cannot_encrypt),
                e.toString()
            )
            mPlaintextView?.requestFocus()
        } catch (e: IllegalArgumentException) {
            mCiphertextView?.error = String.format(
                "%s: %s",
                getString(R.string.error_cannot_encrypt),
                e.toString()
            )
            mPlaintextView?.requestFocus()
        }
    }

    private fun attemptDecrypt() {
        mPlaintextView?.error = null
        mPlaintextView?.setText("")
        mCiphertextView?.error = null
        try {
            val cipherText =
                base64Decode(mCiphertextView?.text.toString())
            val plainText =
                mApplication?.aead?.decrypt(cipherText, EMPTY_ASSOCIATED_DATA)
            mPlaintextView?.setText(String(plainText!!, StandardCharsets.UTF_8))
        } catch (e: GeneralSecurityException) {
            mPlaintextView?.error = String.format(
                "%s: %s",
                getString(R.string.error_cannot_decrypt),
                e.toString()
            )
            mCiphertextView?.requestFocus()
        } catch (e: IllegalArgumentException) {
            mPlaintextView?.error = String.format(
                "%s: %s",
                getString(R.string.error_cannot_decrypt),
                e.toString()
            )
            mCiphertextView?.requestFocus()
        }
    }

    companion object {
        private val EMPTY_ASSOCIATED_DATA = ByteArray(0)
        private fun base64Encode(input: ByteArray) = Base64.encodeToString(input, Base64.DEFAULT)
        private fun base64Decode(input: String) = Base64.decode(input, Base64.DEFAULT)
    }
}