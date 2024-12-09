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
    STACKS=$(grep --no-filename -rE -e "DEFINE_(SPECIAL_)?STACK_OF\([A-Z_0-9a-z]+\)" -e "DEFINE_NAMED_STACK_OF\([A-Z_0-9a-z]+, +[A-Z_0-9a-z:]+\)" "$1/"* | grep -v '//' | grep -v '#' | $sed -e 's/DEFINE_\(SPECIAL_\)\?STACK_OF(\(.*\))/\2/' -e 's/DEFINE_NAMED_STACK_OF(\(.*\), .*)/\1/')
    STACK_FUNCTIONS=("call_free_func" "call_copy_func" "call_cmp_func" "new" "new_null" "num" "zero" "value" "set" "free" "pop_free" "insert" "delete" "delete_ptr" "find" "shift" "push" "pop" "dup" "sort" "is_sorted" "set_cmp_func" "deep_copy")

    for s in $STACKS; do
        for f in "${STACK_FUNCTIONS[@]}"; do
            echo "#define sk_${s}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, sk_${s}_${f})" >> "$1/include/openssl/boringssl_prefix_symbols.h"
        done
    done

    # Now pull out all LHASH_OF functions.
    LHASHES=$(grep --no-filename -rE "DEFINE_LHASH_OF\([A-Z_0-9a-z]+\)" "$1/"* | grep -v '//' | grep -v '#' | grep -v '\\$' | $sed 's/DEFINE_LHASH_OF(\(.*\))/\1/')
    LHASH_FUNCTIONS=("call_cmp_func" "call_hash_func" "new" "free" "num_items" "retrieve" "call_cmp_key" "retrieve_key" "insert" "delete" "call_doall" "call_doall_arg" "doall" "doall_arg")

    for l in $LHASHES; do
        for f in "${LHASH_FUNCTIONS[@]}"; do
            echo "#define lh_${l}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, lh_${l}_${f})" >> "$1/include/openssl/boringssl_prefix_symbols.h"
        done
    done
}


# This function handles mangling the symbols in BoringSSL.
function mangle_symbols {
    echo "GENERATING mangled symbol list"
    (
        # We need a .a: may as well get SwiftPM to give it to us.
        # Temporarily enable the product we need.
        $sed -i -e 's/MANGLE_START/MANGLE_START*\//' -e 's/MANGLE_END/\/*MANGLE_END/' "${HERE}/Package.swift"

        export GOPATH="${TMPDIR}"

        # Begin by building for macOS. We build for two target triples, Intel
        # and Apple Silicon
        swift build --triple "x86_64-apple-macosx" --product CNIOBoringSSL
        swift build --triple "arm64-apple-macosx" --product CNIOBoringSSL
        (
            cd "${SRCROOT}"
            go mod tidy -modcacherw
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-macOS-intel.txt" "${HERE}/.build/x86_64-apple-macosx/debug/libCNIOBoringSSL.a"
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-macOS-as.txt" "${HERE}/.build/arm64-apple-macosx/debug/libCNIOBoringSSL.a"
        )

        # Now build for iOS. We use xcodebuild for this because SwiftPM doesn't
        # meaningfully support it. Unfortunately we must archive ourselves.
        #
        # If xcodebuild complains about not finding the scheme, make sure there
        # isn't a .xcodeproj kicking around.
        xcodebuild -sdk iphoneos -scheme CNIOBoringSSL -derivedDataPath "${TMPDIR}/iphoneos-deriveddata" -destination generic/platform=iOS
        ar -r "${TMPDIR}/libCNIOBoringSSL-iosarm64.a" "${TMPDIR}/iphoneos-deriveddata/Build/Products/Debug-iphoneos/CNIOBoringSSL.o"

        (
            cd "${SRCROOT}"
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-iOS.txt" "${TMPDIR}/libCNIOBoringSSL-iosarm64.a"
        )

        # Now cross compile for our targets.
        docker run -t -i --rm --privileged -v"$(pwd)":/src -w/src --platform linux/arm64 swift:5.9-jammy \
            swift build --product CNIOBoringSSL
        docker run -t -i --rm --privileged -v"$(pwd)":/src -w/src --platform linux/amd64 swift:5.9-jammy \
            swift build --product CNIOBoringSSL

        # Now we need to generate symbol mangles for Linux. We can do this in
        # one go for all of them.
        (
            cd "${SRCROOT}"
            go run "util/read_symbols.go" -obj-file-format elf -out "${TMPDIR}/symbols-linux-all.txt" "${HERE}"/.build/*-unknown-linux-gnu/debug/libCNIOBoringSSL.a
        )

        # Now we concatenate all the symbols together and uniquify it.
        cat "${TMPDIR}"/symbols-*.txt | sort | uniq > "${TMPDIR}/symbols.txt"

        # Use this as the input to the mangle.
        (
            cd "${SRCROOT}"
            go run "util/make_prefix_headers.go" -out "${HERE}/${DSTROOT}/include/openssl" "${TMPDIR}/symbols.txt"
        )

        # Remove the product, as we no longer need it.
        $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
    )

    # Now remove any weird symbols that got in and would emit warnings.
    $sed -i -e '/#define .*\..*/d' "${DSTROOT}"/include/openssl/boringssl_prefix_symbols*.h

    # Now edit the headers again to add the symbol mangling.
    echo "ADDING symbol mangling"
    perl -pi -e '$_ .= qq(\n#define BORINGSSL_PREFIX CNIOBoringSSL\n) if /#define OPENSSL_HEADER_BASE_H/' "$DSTROOT/include/openssl/base.h"

    while IFS= read -r -d '' assembly_file
    do
        $sed -i '1 i #define BORINGSSL_PREFIX CNIOBoringSSL' "$assembly_file"
    done <   <(find "$DSTROOT" -name "*.S" -print0)
    namespace_inlines "$DSTROOT"
}


# BoringSSL includes a few non-namespaced C++ structures. These aren't namespaced because they're exposed
# in C-land, which doesn't know about the namespacing. Sadly, these structures include constructors and destructors,
# and if those aren't namespaced we're still able to conflict.
#
# This function is responsible for identifying them and manually cleaning them up. We run this only on
# macOS because we don't believe that the cross-platform architectures will hit any other structures.
function mangle_cpp_structures {
    echo "MANGLING C++ structures"
    (
        # We need a .a: may as well get SwiftPM to give it to us.
        # Temporarily enable the product we need.
        $sed -i -e 's/MANGLE_START/MANGLE_START*\//' -e 's/MANGLE_END/\/*MANGLE_END/' "${HERE}/Package.swift"

        # Build for macOS.
        swift build --product CNIOBoringSSL

        # Woah, this is a hell of a command! What does it do?
        #
        # The nm command grabs all global defined symbols. We then run the C++ demangler over them and look for methods with '::' in them:
        # these are C++ methods. We then exclude any that contain CNIOBoringSSL (as those are already namespaced!) and any that contain swift
        # (as those were put there by the Swift runtime, not us). This gives us a list of symbols. The following cut command
        # grabs the type name from each of those (the bit preceding the '::'). Then, we sort and uniqify that list.
        # Finally, we remove any symbol that ends in std. This gives us all the structures that need to be renamed.
        structures=$(nm -gUj "$(swift build --show-bin-path)/libCNIOBoringSSL.a" | c++filt | grep "::" | grep -v -e "CNIOBoringSSL" -e "swift" | cut -d : -f1 | grep -v "std$" | $sed -E -e 's/([^<>]*)(<[^<>]*>)?/\1/' | sort | uniq)

        for struct in ${structures}; do
            echo "#define ${struct} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, ${struct})" >> "${DSTROOT}/include/CNIOBoringSSL_boringssl_prefix_symbols.h"
        done

        # Remove the product, as we no longer need it.
        $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
    )
}

case "$(uname -s)" in
    Darwin)
        sed=gsed
        ;;
    *)
	# shellcheck disable=SC2209
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
rm -rf $DSTROOT/third_party
rm -rf $DSTROOT/gen

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
    python3 "${HERE}/scripts/build-asm.py"
)

PATTERNS=(
'include/openssl/*.h'
'include/openssl/*/*.h'
'ssl/*.h'
'ssl/*.cc'
'crypto/*.h'
'crypto/*.cc'
'crypto/*/*.h'
'crypto/*/*.cc'
'crypto/*/*.S'
'crypto/*/*/*.h'
'crypto/*/*/*.cc.inc'
'crypto/*/*/*.S'
'crypto/*/*/*/*.cc.inc'
'gen/crypto/*.cc'
'gen/crypto/*.S'
'gen/bcm/*.S'
'third_party/fiat/*.h'
'third_party/fiat/asm/*.S'
#'third_party/fiat/*.c'
)

EXCLUDES=(
'*_test.*'
'test_*.*'
'test'
'example_*.cc'
)

echo "COPYING boringssl"
for pattern in "${PATTERNS[@]}"
do
  for i in $SRCROOT/$pattern; do
    path=${i#"$SRCROOT"}
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

mangle_symbols

echo "RENAMING header files"
(
    # We need to rearrange a coouple of things here, the end state will be:
    # - Headers from 'include/openssl/' will be moved up a level to 'include/'
    # - Their names will be prefixed with 'CNIOBoringSSL_'
    # - The headers prefixed with 'boringssl_prefix_symbols' will also be prefixed with 'CNIOBoringSSL_'
    # - Any include of another header in the 'include/' directory will use quotation marks instead of angle brackets

    # Let's move the headers up a level first.
    cd "$DSTROOT"
    mv include/openssl/* include/
    rmdir "include/openssl"

    # Now let's remove the pki subdirectory, as we don't need it.
    rm -rf include/pki

    # Now change the imports from "<openssl/X> to "<CNIOBoringSSL_X>", apply the same prefix to the 'boringssl_prefix_symbols' headers.
    # shellcheck disable=SC2038
    find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" -or -name "*.cc.inc" | xargs $sed -i -r -e 's#include <openssl/(([^/>]+/)*)(.+.h)>#include <\1CNIOBoringSSL_\3>#' -e 's+include <boringssl_prefix_symbols+include <CNIOBoringSSL_boringssl_prefix_symbols+' -e 's#include "openssl/(([^/>]+/)*)(.+.h)"#include "\1CNIOBoringSSL_\3"#'

    # Okay now we need to rename the headers adding the prefix "CNIOBoringSSL_".
    pushd include
    for x in *.h; do mv -- "$x" "CNIOBoringSSL_${x}"; done
    for x in **/*.h; do mv -- "$x" "${x%/*}/CNIOBoringSSL_${x##*/}"; done

    # Finally, make sure we refer to them by their prefixed names, and change any includes from angle brackets to quotation marks.
    # shellcheck disable=SC2038
    find . -name "*.h" | xargs $sed -i -r -e 's#include "(([^/"]+/)*)(.+.h)"#include "\1CNIOBoringSSL_\3"#' -e 's/include <CNIOBoringSSL_(.*)>/include "CNIOBoringSSL_\1"/'
    popd
)

echo "PATCHING BoringSSL"
git apply "${HERE}/scripts/patch-1-inttypes.patch"
git apply "${HERE}/scripts/patch-2-inttypes.patch"
git apply "${HERE}/scripts/patch-3-more-inttypes.patch"

# We need to avoid having the stack be executable. BoringSSL does this in its build system, but we can't.
echo "PROTECTING against executable stacks"
(
    cd "$DSTROOT"
    # shellcheck disable=SC2038
    find . -name "*.S" | xargs $sed -i '$ a #if defined(__linux__) && defined(__ELF__)\n.section .note.GNU-stack,"",%progbits\n#endif\n'
)

mangle_cpp_structures

# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"
cat << EOF > "$DSTROOT/include/CNIOBoringSSL.h"
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#ifndef C_NIO_BORINGSSL_H
#define C_NIO_BORINGSSL_H

#include "CNIOBoringSSL_aead.h"
#include "CNIOBoringSSL_aes.h"
#include "CNIOBoringSSL_arm_arch.h"
#include "CNIOBoringSSL_asm_base.h"
#include "CNIOBoringSSL_asn1_mac.h"
#include "CNIOBoringSSL_asn1t.h"
#include "CNIOBoringSSL_base.h"
#include "CNIOBoringSSL_bio.h"
#include "CNIOBoringSSL_blake2.h"
#include "CNIOBoringSSL_blowfish.h"
#include "CNIOBoringSSL_bn.h"
#include "CNIOBoringSSL_boringssl_prefix_symbols.h"
#include "CNIOBoringSSL_boringssl_prefix_symbols_asm.h"
#include "CNIOBoringSSL_cast.h"
#include "CNIOBoringSSL_chacha.h"
#include "CNIOBoringSSL_ctrdrbg.h"
#include "CNIOBoringSSL_cmac.h"
#include "CNIOBoringSSL_conf.h"
#include "CNIOBoringSSL_cpu.h"
#include "CNIOBoringSSL_curve25519.h"
#include "CNIOBoringSSL_des.h"
#include "CNIOBoringSSL_dtls1.h"
#include "CNIOBoringSSL_e_os2.h"
#include "CNIOBoringSSL_ec.h"
#include "CNIOBoringSSL_ec_key.h"
#include "CNIOBoringSSL_ecdsa.h"
#include "CNIOBoringSSL_err.h"
#include "CNIOBoringSSL_evp.h"
#include "CNIOBoringSSL_hkdf.h"
#include "CNIOBoringSSL_hmac.h"
#include "CNIOBoringSSL_hpke.h"
#include "CNIOBoringSSL_hrss.h"
#include "CNIOBoringSSL_kdf.h"
#include "CNIOBoringSSL_md4.h"
#include "CNIOBoringSSL_md5.h"
#include "CNIOBoringSSL_mldsa.h"
#include "CNIOBoringSSL_mlkem.h"
#include "CNIOBoringSSL_obj_mac.h"
#include "CNIOBoringSSL_objects.h"
#include "CNIOBoringSSL_opensslv.h"
#include "CNIOBoringSSL_ossl_typ.h"
#include "CNIOBoringSSL_pkcs12.h"
#include "CNIOBoringSSL_poly1305.h"
#include "CNIOBoringSSL_rand.h"
#include "CNIOBoringSSL_rc4.h"
#include "CNIOBoringSSL_ripemd.h"
#include "CNIOBoringSSL_rsa.h"
#include "CNIOBoringSSL_safestack.h"
#include "CNIOBoringSSL_service_indicator.h"
#include "CNIOBoringSSL_sha.h"
#include "CNIOBoringSSL_siphash.h"
#include "CNIOBoringSSL_slhdsa.h"
#include "CNIOBoringSSL_srtp.h"
#include "CNIOBoringSSL_ssl.h"
#include "CNIOBoringSSL_time.h"
#include "CNIOBoringSSL_trust_token.h"
#include "CNIOBoringSSL_type_check.h"
#include "CNIOBoringSSL_x509_vfy.h"
#include "CNIOBoringSSL_x509v3.h"
#include "experimental/CNIOBoringSSL_kyber.h"

#endif  // C_NIO_BORINGSSL_H
EOF
cat << EOF > "$DSTROOT/include/module.modulemap"
module CNIOBoringSSL {
    umbrella header "CNIOBoringSSL.h"
    export *
}
EOF

echo "RECORDING BoringSSL revision"
$sed -i -e "s/BoringSSL Commit: [0-9a-f]\+/BoringSSL Commit: ${BORINGSSL_REVISION}/" "$HERE/Package"*.swift
echo "This directory is derived from BoringSSL cloned from https://boringssl.googlesource.com/boringssl at revision ${BORINGSSL_REVISION}" > "$DSTROOT/hash.txt"

echo "CLEANING temporary directory"
rm -rf "${TMPDIR}"

