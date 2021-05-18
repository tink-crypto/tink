# A Homebrew formula for Tinkey on Linux and macOS.
# Usage:
# brew tap google/tink https://github.com/google/tink
# brew install tinkey

class Tinkey < Formula
  desc "A command line tool to generate and manipulate keysets for the Tink cryptography library"
  homepage "https://github.com/google/tink/tree/master/tools/tinkey"
  url "https://storage.googleapis.com/tinkey/tinkey-1.6.0.tar.gz"
  sha256 "51d9694a704d00fbac04862a6427ad5f17bf59f91d5e963517d8799141e737c0"

  bottle :unneeded

  def install
    bin.install "tinkey"
    bin.install "tinkey_deploy.jar"
  end
end
