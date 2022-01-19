# A Homebrew formula for Tinkey on Linux and macOS.
# Usage:
# brew tap google/tink https://github.com/google/tink
# brew install tinkey

class Tinkey < Formula
  desc "A command line tool to generate and manipulate keysets for the Tink cryptography library"
  homepage "https://github.com/google/tink/tree/master/tools/tinkey"
  url "https://storage.googleapis.com/tinkey/tinkey-1.6.1.tar.gz"
  sha256 "156e902e212f55b6747a55f92da69a7e10bcbd00f8942bc1568c0e7caefff3e1"

  def install
    bin.install "tinkey"
    bin.install "tinkey_deploy.jar"
  end
end
