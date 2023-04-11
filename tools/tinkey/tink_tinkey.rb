# A Homebrew formula for Tinkey on Linux and macOS.
# Usage:
# brew tap tink-crypto/tink-tinkey https://github.com/tink-crypto/tink-tinkey
# brew install tinkey

class Tinkey < Formula
  desc "A command line tool to generate and manipulate keysets for the Tink cryptography library"
  homepage "https://github.com/tink-crypto/tink-tinkey"
  url "https://storage.googleapis.com/tinkey/tinkey-1.8.0.tar.gz"
  sha256 "ee262e3705837366188920687a35a224468380f58f02916ca0567d1e4b66cdcf"

  def install
    bin.install "tinkey"
    bin.install "tinkey_deploy.jar"
  end
end
