# A Homebrew formula for Tinkey on Linux and macOS.
# Usage:
# brew tap google/tink https://github.com/google/tink
# brew install tinkey

class Tinkey < Formula
  desc "A command line tool to generate and manipulate keysets for the Tink cryptography library"
  homepage "https://github.com/google/tink/tree/master/tools/tinkey"
  url "https://storage.googleapis.com/tinkey/tinkey-1.5.0.tar.gz"
  sha256 "bd148e684ffba85b8499bcfe29c8ed1e9dedef52eddd35dabb0a34e396790b90"

  bottle :unneeded

  def install
    bin.install "tinkey"
    bin.install "tinkey_deploy.jar"
  end
end
