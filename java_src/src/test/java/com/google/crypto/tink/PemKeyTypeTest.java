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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PemKeyType */
@RunWith(JUnit4.class)
public final class PemKeyTypeTest {

  @Test
  public void readKey_rsaPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.RSA_PSS_2048_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(RSAPublicKey.class);
    RSAPublicKey rsa = (RSAPublicKey) key;
    assertThat(rsa.getModulus()).isNotNull();
    assertThat(rsa.getPublicExponent()).isNotNull();
  }

  @Test
  public void readKey_rsaPrivateKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Bn6pA4wksGPK\n"
            + "xhRrJnk0mcyKk5hSCFlrlwCs1OUaWAQTMWzFrMW0mdR4FCG6mw2K91rla2F51af8\n"
            + "IJjy/E02ampBZrFfIlTbHLPOXdSrgL2L1a213zS2AsMZ1NAEKZwG5eJDf9Ym4oTC\n"
            + "nut50YILgwtwYHLvov0ciJjR6q85+59UznZx6itVEqQpDT7Fi7QWOaGb5mMLHCcF\n"
            + "m5oyUFvrxvQrMB+fss8rYkwbZZhwK76u04tf2ZQdZh/2rcpl/7JR0fMUvO0IYfow\n"
            + "7GduISnlrLoDpst1lPk8YM75sq7uRe3Gqt0x+EHuHzf9Y8z/POu7AYo9Yxs9SYp5\n"
            + "NIcEu0GfAgMBAAECggEAcYsagcX6o01BdfoX6nzZRMJ7mlN28FLKbQZLChOmJjpw\n"
            + "e4alQNoMqfsbK0g89gscKoclBNXLj19OihrFQjbKCcpJUCVLhz+cLpUun7hZ7RdZ\n"
            + "X1AyDloz4pXYa4jv9ROLfT7lXA2erOytbzm4yV+TQJBqH/qebcfnQYvbfShTmJcp\n"
            + "fH2lNYhn5g3+jHb79aakwGTg9q8b88lkDL7gB66jvoEBe3JtCItplXuET5UfrDI/\n"
            + "8+ef1n2vMqPc6GIyCrD0p4JV90D3OBOWq41V+AwbOKFJ8kGKJ0d5W0SxQJL6F9IV\n"
            + "rg4zx4mXRxq5cWKLiXd2qAu97n7d9g7KbOy6UPMigQKBgQDj8VJGeEn0wth/WmUG\n"
            + "RTh4t1R5lrFAZ5ZuM2OZ4r5qjC6o8GUlHwXovc3kcz1whFI0MvOq1rdZkO+tvtvO\n"
            + "kcsJfOK4Xfoi/TyhKoYZjXbTEAlTE1HwckaTfNex2B02dfiv11nRJ57bEwbhL3V7\n"
            + "rzaOJl+0KXdbG00W2Ip7AJ8AxwKBgQDTK1fz0p90HDPM+V2YuTtO/VavD5vJj5CJ\n"
            + "2HYezM9l4Lp/7r+++PzjuzikpflhTUeijxNyOFGKtH8KEpEtyVGx1UBjK8VwM4sX\n"
            + "7k+GZ2e3upisagV/GisnEB7lhOnoLUqD8x7xTRHx2RBdw44wUqUGmC/zZ552DHrR\n"
            + "hvNhKEyQaQKBgQDFNr+WlPB3wjUKSq1pdW5ck1GVOVn2fSlcAz5DoDhbexnLtOHt\n"
            + "8h9stPt0kngv52wwGX1U7B0KcynLy3vmB6IBfXmzRivrJerVDjOj3A9YoWFP7UFR\n"
            + "pa2GYddE2dS8j+kwSkQ9f+gjZxzmq+cbsgajinP3LoFD5CUYhRWbQnhPdQKBgDZw\n"
            + "IxFhR+gH6Ta7Rmy7u9VmK/WfYXr5vro6imDwTbsmzw1yAA58Y71Vo4mWnA6AfKok\n"
            + "lk/IwwSt+V4gYTrbfmsI3btzKkf9kasOrYOpnqxXt0ojXt1gYqWEW2Kx/Bb1rhMM\n"
            + "Fvr/8lNVsQlrA3njpFVp4FqwaMJn/zWKw61VVT+ZAoGAOkcDDz6GihRX8CkK5ejh\n"
            + "qV/vI/m42Qsg2OddE4yUvAHpki1gEmqK9scULrsyztCGtSzx+l3TibzmG/bGbsTJ\n"
            + "1HzQiotarX2fSCAgA8wZvc4F0eQbVo5gxDrsRKIwMSgr1GrEfqd93yuKMDp4TifH\n"
            + "P54N1bX5PnvnE2HC22dRMNQ=\n"
            + "-----END PRIVATE KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.RSA_PSS_2048_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(RSAPrivateKey.class);
    RSAPrivateKey rsa = (RSAPrivateKey) key;
    assertThat(rsa.getModulus()).isNotNull();
    assertThat(rsa.getPrivateExponent()).isNotNull();
  }

  @Test
  public void readKey_ecPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.ECDSA_P256_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(ECPublicKey.class);
  }

  @Test
  public void readKey_ecPrivateKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghpeIjMYdV40aVFTt\n"
            + "u8kJPLduSnj6HBamgrrZwAhKLrahRANCAAThRzShRQmj7MChwiZWH6k6PpksS5HM\n"
            + "8xP2XD/CiUeWCLR8g30Zh9K7NvufcfZxyJ3I6NTilbGcEM5/VgqAt8z3\n"
            + "-----END PRIVATE KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.ECDSA_P256_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(ECPrivateKey.class);
  }

  @Test
  public void readKey_withCommentHeader_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "Version: 1.0.0\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.RSA_PSS_2048_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(RSAPublicKey.class);
    RSAPublicKey rsa = (RSAPublicKey) key;
    assertThat(rsa.getModulus()).isNotNull();
    assertThat(rsa.getPublicExponent()).isNotNull();
  }

  @Test
  public void readKey_withCommentHeaderOutsideMarkers_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n"
            + "Version: 1.0.0\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.RSA_PSS_2048_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(RSAPublicKey.class);
    RSAPublicKey rsa = (RSAPublicKey) key;
    assertThat(rsa.getModulus()).isNotNull();
    assertThat(rsa.getPublicExponent()).isNotNull();
  }

  @Test
  public void readKey_withBeginRsaPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN RSA PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END RSA PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.RSA_PSS_2048_SHA256.readKey(reader);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(RSAPublicKey.class);
    RSAPublicKey rsa = (RSAPublicKey) key;
    assertThat(rsa.getModulus()).isNotNull();
    assertThat(rsa.getPublicExponent()).isNotNull();
  }

  @Test
  public void readKey_withEd25519_shouldFail() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MCowBQYDK2VwAyEAfU0Of2FTpptiQrUiq77mhf2kQg+INLEIw72uNp71Sfo=\n"
            + "-----END PUBLIC KEY-----\n";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.ECDSA_P256_SHA256.readKey(reader);
    assertThat(key).isNull();
  }

  @Test
  public void readKey_withSecp256k1_shouldFail() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuDj/ROW8F3vyEYnQdmCC/J2EMiaIf8l2\n"
            + "A3EQC37iCm/wyddb+6ezGmvKGXRJbutW3jVwcZVdg8Sxutqgshgy6Q==\n"
            + "-----END PUBLIC KEY-----";
    BufferedReader reader = new BufferedReader(new StringReader(pem));
    Key key = PemKeyType.ECDSA_P256_SHA256.readKey(reader);
    assertThat(key).isNull();
  }
}
