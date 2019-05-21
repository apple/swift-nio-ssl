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
# This was substantially adapted from grpc-swift's vendor-boringssl.sh script.
# The license for the original work is reproduced below. See NOTICES.txt for
# more.
#
# Copyright 2016, gRPC Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script creates a vendored copy of BoringSSL that is
# suitable for building with the Swift Package Manager.
#
# Usage: 
#   1. Run this script in the package root. It will place 
#      a local copy of the BoringSSL sources in Sources/CNIOBoringSSL.
#      Any prior contents of Sources/CNIOBoringSSL will be deleted.
#
set -eou pipefail

HERE=$(pwd)
DSTROOT=Sources/CNIOBoringSSL
TMPDIR=$(mktemp -d /tmp/.workingXXXXXX)
SRCROOT="${TMPDIR}/src/boringssl.googlesource.com/boringssl"

# This function namespaces the awkward inline functions declared in OpenSSL
# and BoringSSL.
function namespace_inlines {
    # Pull out all STACK_OF functions.
    STACKS=$(grep --no-filename -rE "DEFINE_(SPECIAL_)?STACK_OF\([A-Z_0-9a-z]+\)" "$1/"* | grep -v '//' | grep -v '#' | gsed 's/DEFINE_\(SPECIAL_\)\?STACK_OF(\(.*\))/\2/')
    STACK_FUNCTIONS=("call_free_func" "call_copy_func" "call_cmp_func" "new" "new_null" "num" "zero" "value" "set" "free" "pop_free" "insert" "delete" "delete_ptr" "find" "shift" "push" "pop" "dup" "sort" "is_sorted" "set_cmp_func" "deep_copy")

    for s in $STACKS; do
        for f in "${STACK_FUNCTIONS[@]}"; do
            echo "#define sk_${s}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, sk_${s}_${f})" >> "$1/boringssl_prefix_symbols.h"
        done
    done

    # Now pull out all LHASH_OF functions.
    LHASHES=$(grep --no-filename -rE "DECLARE_LHASH_OF\([A-Z_0-9a-z]+\)" "$1/"* | grep -v '//' | grep -v '#' | grep -v '\\$' | gsed 's/DECLARE_LHASH_OF(\(.*\))/\1/')
    LHASH_FUNCTIONS=("call_cmp_func" "call_hash_func" "new" "free" "num_items" "retrieve" "call_cmp_key" "retrieve_key" "insert" "delete" "call_doall" "call_doall_arg" "doall" "doall_arg")

    for l in $LHASHES; do
        for f in "${LHASH_FUNCTIONS[@]}"; do
            echo "#define lh_${l}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, lh_${l}_${f})" >> "$1/boringssl_prefix_symbols.h"
        done
    done
}

case "$(uname -s)" in
    Darwin)
        sed=gsed
        ;;
    *)
        sed=sed
        ;;
esac

if ! hash ${sed} 2>/dev/null; then
    echo "You need sed \"${sed}\" to run this script ..."
    echo
    echo "On macOS: brew install gnu-sed"
    exit 43
fi

echo "REMOVING any previously-vendored BoringSSL code"
rm -rf $DSTROOT/include
rm -rf $DSTROOT/ssl
rm -rf $DSTROOT/crypto
rm -rf $DSTROOT/err_data.c

echo "CLONING boringssl"
mkdir -p "$SRCROOT"
git clone https://boringssl.googlesource.com/boringssl "$SRCROOT"
cd "$SRCROOT"
BORINGSSL_REVISION=$(git rev-parse HEAD)
cd "$HERE"
echo "CLONED boringssl@${BORINGSSL_REVISION}"

echo "OBTAINING submodules"
(
    cd "$SRCROOT"
    git submodule update --init
)

echo "GENERATING assembly helpers"
(
    cd "$SRCROOT"
    cd ..
    mkdir -p "${SRCROOT}/crypto/third_party/sike/asm"
    python "${HERE}/scripts/build-asm.py"
)

PATTERNS=(
'include/openssl/*.h'
'ssl/*.h'
'ssl/*.cc'
'crypto/*.h'
'crypto/*.c'
'crypto/*/*.h'
'crypto/*/*.c'
'crypto/*/*.S'
'crypto/*/*/*.h'
'crypto/*/*/*.c'
'crypto/*/*/*.S'
'crypto/*/*/*/*.c'
'crypto/*/*/*/*.S'
'third_party/fiat/*.h'
'third_party/fiat/*.c'
'third_party/sike/*.h'
'third_party/sike/*.c'
'third_party/sike/asm/*.c'
)

EXCLUDES=(
'*_test.*'
'test_*.*'
'test'
'example_*.c'
)

echo "COPYING boringssl"
for pattern in "${PATTERNS[@]}" 
do
  for i in $SRCROOT/$pattern; do
    path=${i#$SRCROOT}
    dest="$DSTROOT$path"
    dest_dir=$(dirname "$dest")
    mkdir -p "$dest_dir"
    cp "$SRCROOT/$path" "$dest"
  done
done

for exclude in "${EXCLUDES[@]}" 
do
  echo "EXCLUDING $exclude"
  find $DSTROOT -d -name "$exclude" -exec rm -rf {} \;
done

echo "GENERATING err_data.c"
(
    cd "$SRCROOT/crypto/err"
    go run err_data_generate.go > "${HERE}/${DSTROOT}/crypto/err/err_data.c"
)

echo "DELETING crypto/fipsmodule/bcm.c"
rm -f $DSTROOT/crypto/fipsmodule/bcm.c

echo "FIXING missing include"
perl -pi -e '$_ .= qq(\n#include <openssl/cpu.h>\n) if /#include <openssl\/err.h>/' "$DSTROOT/crypto/fipsmodule/ec/p256-x86_64.c"


echo "GENERATING mangled symbol list"
(
    # We need a .a: may as well get SwiftPM to give it to us.
    # Temporarily enable the product we need.
    $sed -i -e 's/MANGLE_START/MANGLE_START*\//' -e 's/MANGLE_END/\/*MANGLE_END/' "${HERE}/Package.swift"
    swift build --product CNIOBoringSSL
    export GOPATH="${TMPDIR}"
    go run "${SRCROOT}/util/read_symbols.go" -out "${TMPDIR}/symbols.txt" "${HERE}/.build/debug/libCNIOBoringSSL.a"
    go run "${SRCROOT}/util/make_prefix_headers.go" -out "${HERE}/${DSTROOT}/include" "${TMPDIR}/symbols.txt"
    
    # Remove the product, as we no longer need it.
    $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
)

# Now edit the headers again to add the symbol mangling.
echo "ADDING symbol mangling"
perl -pi -e '$_ .= qq(\n#define BORINGSSL_PREFIX CNIOBoringSSL\n) if /#define OPENSSL_HEADER_BASE_H/' "$DSTROOT/include/openssl/base.h"

for assembly_file in $(find "$DSTROOT" -name "*.S")
do
    $sed -i '1 i #define BORINGSSL_PREFIX CNIOBoringSSL' "$assembly_file"
done
namespace_inlines "$DSTROOT/include"

echo "RENAMING header files"
(
    cd "$DSTROOT"
    mv "include/openssl" "include/CNIOBoringSSL"
    find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" | xargs $sed -i -e 's_include <openssl/_include <CNIOBoringSSL/_'
)

# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"
cat << EOF > "$DSTROOT/include/module.modulemap"
module CNIOBoringSSL {
  header "CNIOBoringSSL/base.h"
  header "CNIOBoringSSL/conf.h"
  header "CNIOBoringSSL/evp.h"
  header "CNIOBoringSSL/err.h"
  header "CNIOBoringSSL/bio.h"
  header "CNIOBoringSSL/ssl.h"
  header "CNIOBoringSSL/sha.h"
  header "CNIOBoringSSL/md5.h"
  header "CNIOBoringSSL/hmac.h"
  header "CNIOBoringSSL/rand.h"
  header "CNIOBoringSSL/pkcs12.h"
  header "CNIOBoringSSL/x509v3.h"
  header "CNIOBoringSSL/rsa.h"
  header "CNIOBoringSSL/ec.h"
  header "CNIOBoringSSL/ecdsa.h"
  header "CNIOBoringSSL/ec_key.h"
  export *
}
EOF

echo "RECORDING BoringSSL revision"
$sed -i -e "s/BoringSSL Commit: [0-9a-f]\+/BoringSSL Commit: ${BORINGSSL_REVISION}/" "$HERE/Package.swift"
echo "This directory is derived from BoringSSL cloned from https://boringssl.googlesource.com/boringssl at revision ${BORINGSSL_REVISION}" > "$DSTROOT/hash.txt"

echo "CLEANING temporary directory"
rm -rf "${TMPDIR}"

