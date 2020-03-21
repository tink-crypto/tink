# PKCS11 HSM/Token support

This integration allows for the AEAD to be used by Tink to be stored in a PKCS11 device.

## Setup

### Provide a *crypto11.Config

As this is focused on support HSMs, there is an assumption that you have at least configured your needed PKCS11 library/client, and generared a Slot/PIN for authentication to the device.

You must provide a *crypto11.Config pointer that has the Library, PIN, and Slot or Label to authenticate with.  

For more details on configuration and usage of the crypto11 package, please refer to the project here: [https://github.com/ThalesIgnite/crypto11](https://github.com/ThalesIgnite/crypto11)


## Usage - HSM or Wrapped Key

This KMSClient supports HSM AEAD and Wrapped AEAD keys for the GetAEAD() function.  

Both are using AES256GCM to perform JWK/JWE based encryption operations using GOSE [https://github.com/ThalesIgnite/gose](https://github.com/ThalesIgnite/gose) which are optimized helpers for all things JOSE.  

### HSM

HSM Keys reside in the pkcs11 token/slot, and a cipher.AEAD handle to the PKCS11 key handle which is then used to support the tink.AEAD interface transparently.

HSM Keys are:
- SecretKeys in the HSM
- Session based using a pkcs11 session to the HSM for each KMSClient provided
- The AEAD handle will be accessible as long as the session is open
- Good for "remove the HSM" use cases that will close all access to the AEAD even to tink

The keyURI for a HSM key is `pkcs11://ee2c5de3-335c-428b-8168-5daf299e97f3`  where `ee2c5de3-335c-428b-8168-5daf299e97f3` is the key ID (not label) in the device to use.  To have the key auto created if it doesnt' exist yet, simply provide the "autogen" bool to the client.


### Wrapped

Wrapped keys are pre-encrypted JWK keys that were "encrypted" by the HSM Key, and provided as part of the keyURI as a `?blob=JweStringOfEncryptedJwk` query parameter.

Wrapped keys are:
- Secured by the HSM
- Encrypted JWK in JWE string format which makes them portable(JSON, and URL friendly)
- Performs 10X to 1000X faster than a round trip to the HSM each operation
- Reduces stress on the device (less heat, and ops overtime)
- Leveraging authenticated encryption (AEAD wrapped by AEAD in HSM)

All this gives the user flexibility of choice with still sensible crypto in place.

The keyURI for a Wrapped key is `pkcs11://ee2c5de3-335c-428b-8168-5daf299e97f3?blob=eyJhbGciOiJkaXIiLCJraWQiOiJlZTJjNWRlMy0zMzVjLTQyOGItODE2OC01ZGFmMjk5ZTk3ZjMiLCJlbmMiOiJBMjU2R0NNIn0..gdC9cTZntv9QFEsk.EyiZKw3NkPzMIXtyRY7eS_kpMC6pE0VJvbiPA0-epqMq28L-bhxgut1O_smeZ_udVUBr3lYHd2Lrd2Vdv5UXZ3snnE_wx0HZuiTWOn87Jxb8kR9Bz8jcKKaWsIjEZflRGKCpKaZmq4A2VFrG6UI1c5SCXQDBaRteou_SAnwX_k7QkcQZLgprYrPsKXOeB7gJByq7_kpp28EiZVvhOU-m2UEGnB0nBdwhu5Z64l7CAvU5i7Y6V8Kdlw.wO_EE-PVNO36iof68_sZxw`

#### Creating at JWK for the `?blob=JweStringOfEncryptedJwk`

If you already have a JWK file/string you can simply do an Encrypt against the HSM and the resulting Payload is your `JweStringOfEncryptedJwk`

However, if you need to create a JWK file you can do so by using a `*gose.AuthenticatedEncryptionKeyGenerator{}`

```go
	package main
    
    import (
    	"github.com/ThalesIgnite/gose"
    	"github.com/ThalesIgnite/gose/jose"
    	"encoding/json"
    	"fmt"
    ) 
    
    func main() {
    	generator := gose.AuthenticatedEncryptionKeyGenerator{}
     	var keystoreJwk jose.Jwk
        var err error
     	if _, keystoreJwk, err = generator.Generate(jose.Alg(jose.AlgA256GCM), []jose.KeyOps{jose.KeyOpsEncrypt,jose.KeyOpsDecrypt}); err != nil {
     		panic(err)
     	}
     	var jwkString []byte
     	if jwkString, err = json.Marshal(keystoreJwk); err != nil {
     		panic(err)
     	}
        fmt.Printf("JWK : %s", jwkString)
    }

```
## Performance

While Security and Performance often must battle for the implementation detail and based on the needs of your application.

To compare your options we have provided some benchmark tests you can run.

Here's an example run on a 2019 MacBook Pro using a SoftHSM2 to remove hardware/network variance of a given HSM implementation.

```bash
goos: darwin
goarch: amd64
pkg: github.com/google/tink/go/integration/pkcs11kms
BenchmarkPkcs11AEAD_HSM_Encrypt-16        	   12218	     94382 ns/op
BenchmarkPkcs11AEAD_HSM_Decrypt-16        	   12232	     94761 ns/op
BenchmarkPkcs11AEAD_Wrapped_Encrypt-16    	  309532	      3679 ns/op
BenchmarkPkcs11AEAD_Wrapped_Decrypt-16    	  258178	      4647 ns/op
PASS
ok  	github.com/google/tink/go/integration/pkcs11kms	7.978s
```