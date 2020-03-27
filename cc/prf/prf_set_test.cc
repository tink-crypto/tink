// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/prf/prf_set.h"

#include <map>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

class DummyPrf : public Prf {
  util::StatusOr<std::string> Compute(absl::string_view input,
                                      size_t output_length) const override {
    return std::string("DummyPRF");
  }
};

class DummyPrfSet : public PrfSet {
 public:
  uint32_t GetPrimaryId() const override { return 1; }
  const std::map<uint32_t, Prf*>& GetPrfs() const override {
    static const std::map<uint32_t, Prf*>* prfs =
        new std::map<uint32_t, Prf*>({{1, dummy_.get()}});
    return *prfs;
  }

 private:
  std::unique_ptr<Prf> dummy_ = absl::make_unique<DummyPrf>();
};

class BrokenDummyPrfSet : public PrfSet {
 public:
  uint32_t GetPrimaryId() const override { return 1; }
  const std::map<uint32_t, Prf*>& GetPrfs() const override {
    static const std::map<uint32_t, Prf*>* prfs =
        new std::map<uint32_t, Prf*>();
    return *prfs;
  }
};

TEST(PrfSetTest, ComputePrimary) {
  DummyPrfSet prfset;
  auto output = prfset.ComputePrimary("DummyInput", 16);
  EXPECT_TRUE(output.ok()) << output.status();
  BrokenDummyPrfSet broken_prfset;
  auto broken_output = broken_prfset.ComputePrimary("DummyInput", 16);
  EXPECT_FALSE(broken_output.ok())
      << "Expected broken PrfSet to not be able to compute the primary PRF";
}

}  // namespace
}  // namespace tink
}  // namespace crypto
