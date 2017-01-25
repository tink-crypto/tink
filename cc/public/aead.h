// AEAD primitive (Authenticated Encryption with Associated Data, RFC 5116).
// TODO(przydatek): add documentation.

#ifndef K2_PUBLIC_AEAD_H_
#define K2_PUBLIC_AEAD_H_

#include "google/protobuf/stubs/stringpiece.h"
#include "google/protobuf/stubs/statusor.h"

namespace cloud {
namespace k2 {

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

}  // namespace k2
}  // namespace cloud

#endif  // K2_PUBLIC_AEAD_H_

