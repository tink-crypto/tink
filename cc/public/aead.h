// AEAD primitive (Authenticated Encryption with Associated Data, RFC 5116).
// TODO(przydatek): add documentation.

#ifndef TINK_PUBLIC_AEAD_H_
#define TINK_PUBLIC_AEAD_H_

#include "google/protobuf/stubs/stringpiece.h"
#include "google/protobuf/stubs/statusor.h"

namespace cloud {
namespace crypto {
namespace tink {

using google::protobuf::util::StatusOr;
using google::protobuf::StringPiece;

class Aead {
 public:
  virtual StatusOr<std::string> Encrypt(
     StringPiece plaintext, StringPiece associated_data) const = 0;
  virtual StatusOr<std::string> Decrypt(
     StringPiece ciphertext, StringPiece associated_data) const = 0;
  virtual ~Aead() {}
};

}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_PUBLIC_AEAD_H_
