# A Homebrew formula for Tinkey on Linux and macOS.
# Usage:
# brew tap google/tink https://github.com/google/tink
# brew install tinkey

class Tinkey < Formula
  desc "A command line tool to generate and manipulate keysets for the Tink cryptography library"
  homepage "https://github.com/google/tink/tree/master/tools/tinkey"
  url "https://storage.googleapis.com/tinkey/tinkey-1.7.0.tar.gz"
  sha256 "2c9e69e5bc7561ce37918cecd3eeabb4571e01c915c4397bce25796ff04d92a3"

  def install
    bin.install "tinkey"
    bin.install "tinkey_deploy.jar"
  end
end
