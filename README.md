# Cloud Crypto SDK

An open-source SDK that provides cloud customers with cryptographic
functionalities needed to extend key management offering of Cloud KMS.

In particular, Cloud KMS needs support for “Envelope Encryption”, i.e., a
client-side encryption of data with user-generated keys protected by KMS
encryption: cloud user generates a data encryption key (DEK) locally,
encrypts data with DEK, sends DEK to Storky to be encrypted (with a key
managed by Storky), and stores encrypted DEK with encrypted data; at a later
point user can retrieve encrypted data and DEK, use Storky to decrypt DEK,
and use decrypted DEK to decrypt the data. A guiding principles for the
design of the SDK are security, simplicity, and resistance to user errors.
