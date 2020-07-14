# A Homebrew formula for Tinkey on Linux and macOS.
# Usage:
# brew tap google/tink https://github.com/google/tink
# brew install tinkey

class Tinkey < Formula
  desc "A command line tool to generate and manipulate keysets for the Tink cryptography library"
  homepage "https://github.com/google/tink/tree/master/tools/tinkey"
  url "https://storage.googleapis.com/tinkey/tinkey-darwin-x86_64-1.4.0.tar.gz"
  sha256 "cd4a79a3c78084e6d0b4d82cc0e2f903cb0f18d6d75c7c897512f7804be50dba"

  on_linux do
    url "https://storage.googleapis.com/tinkey/tinkey-linux-x86_64-1.4.0.tar.gz"
    sha256 "b36521a05fc59b6541bd4119df9f1cc392a509ed914efe763b92c50b87f4159f"
  end

  bottle :unneeded

  def install
    bin.install "tinkey"
    bin.install "tinkey_deploy.jar"
  end
end
