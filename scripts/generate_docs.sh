#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2018-2019 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -e

my_path="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
root_path="$my_path/.."
version=$(git describe --abbrev=0 --tags || echo "0.0.0")
modules=(NIOSSL)

if [[ "$(uname -s)" == "Linux" ]]; then
  # build code if required
  if [[ ! -d "$root_path/.build/x86_64-unknown-linux" ]]; then
    swift build
  fi
  # setup source-kitten if required
  source_kitten_source_path="$root_path/.SourceKitten"
  if [[ ! -d "$source_kitten_source_path" ]]; then
    git clone https://github.com/jpsim/SourceKitten.git "$source_kitten_source_path"
  fi
  source_kitten_path="$source_kitten_source_path/.build/x86_64-unknown-linux/debug"
  if [[ ! -d "$source_kitten_path" ]]; then
    rm -rf "$source_kitten_source_path/.swift-version"
    cd "$source_kitten_source_path" && swift build && cd "$root_path"
  fi
  # generate
  mkdir -p "$root_path/.build/sourcekitten"
  for module in "${modules[@]}"; do
    if [[ ! -f "$root_path/.build/sourcekitten/$module.json" ]]; then
      "$source_kitten_path/sourcekitten" doc --spm-module $module > "$root_path/.build/sourcekitten/$module.json"
    fi
  done
fi

[[ -d docs/$version ]] || mkdir -p docs/$version
[[ -d swift-nio-ssl.xcodeproj ]] || swift package generate-xcodeproj

# run jazzy
if ! command -v jazzy > /dev/null; then
  gem install jazzy --no-ri --no-rdoc
fi

jazzy_dir="$root_path/.build/jazzy"
rm -rf "$jazzy_dir"
mkdir -p "$jazzy_dir"

module_switcher="$jazzy_dir/README.md"
jazzy_args=(--clean
            --author 'swift-nio team'
            --readme "$module_switcher"
            --author_url https://github.com/apple/swift-nio-ssl
            --github_url https://github.com/apple/swift-nio-ssl
            --theme fullwidth
            --xcodebuild-arguments -scheme,swift-nio-ssl-Package)
cat > "$module_switcher" <<"EOF"
# swift-nio-ssl Docs

SwiftNIO SSL is a Swift package that contains an implementation of TLS based on BoringSSL. This package allows users of SwiftNIO to write protocol clients and servers that use TLS to secure data in flight.

The name is inspired primarily by the names of the library this package uses (BoringSSL), and not because we don't know the name of the protocol. We know the protocol is TLS!

SwiftNIO SSL provides two `ChannelHandlers` to use to secure a data stream: the `NIOSSLClientHandler` and the `NIOSSLServerHandler`. Each of these can be added to a Channel to secure the communications on that channel.

Additionally, we provide a number of low-level primitives for configuring your TLS connections. These will be shown below.

To secure a server connection, you will need a X.509 certificate chain in a file (either PEM or DER, but PEM is far easier), and the associated private key for the leaf certificate. These objects can then be wrapped up in a `TLSConfiguration` object that is used to initialize the `ChannelHandler`.

---

For the API documentation of the other repositories in the SwiftNIO family check:

- [`swift-nio` API docs](https://apple.github.io/swift-nio/docs/current/NIO/index.html)
- [`swift-nio-ssl` API docs](https://apple.github.io/swift-nio-ssl/docs/current/NIOSSL/index.html)
- [`swift-nio-http2` API docs](https://apple.github.io/swift-nio-http2/docs/current/NIOHTTP2/index.html)
- [`swift-nio-extras` API docs](https://apple.github.io/swift-nio-extras/docs/current/NIOExtras/index.html)

EOF

for module in "${modules[@]}"; do
  args=("${jazzy_args[@]}" --output "$jazzy_dir/docs/$version/$module" --docset-path "$jazzy_dir/docset/$version/$module"
        --module "$module" --module-version $version
        --root-url "https://apple.github.io/swift-nio-ssl/docs/$version/$module/")
  if [[ -f "$root_path/.build/sourcekitten/$module.json" ]]; then
    args+=(--sourcekitten-sourcefile "$root_path/.build/sourcekitten/$module.json")
  fi
  jazzy "${args[@]}"
done

# push to github pages
if [[ $PUSH == true ]]; then
  BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
  GIT_AUTHOR=$(git --no-pager show -s --format='%an <%ae>' HEAD)
  git fetch origin +gh-pages:gh-pages
  git checkout gh-pages
  rm -rf "docs/$version"
  rm -rf "docs/current"
  cp -r "$jazzy_dir/docs/$version" docs/
  cp -r "docs/$version" docs/current
  git add --all docs
  echo '<html><head><meta http-equiv="refresh" content="0; url=docs/current/NIOSSL/index.html" /></head></html>' > index.html
  git add index.html
  touch .nojekyll
  git add .nojekyll
  changes=$(git diff-index --name-only HEAD)
  if [[ -n "$changes" ]]; then
    echo -e "changes detected\n$changes"
    git commit --author="$GIT_AUTHOR" -m "publish $version docs"
    git push origin gh-pages
  else
    echo "no changes detected"
  fi
  git checkout -f $BRANCH_NAME
fi
