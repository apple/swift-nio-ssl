#!/usr/bin/env python3
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##
"""Check that BoringSSL's symbol prefixing is complete.

We vendor BoringSSL under a prefix so that a binary can statically link this
copy alongside another copy that uses a different prefix (swift-crypto's
CCryptoBoringSSL, for example -- our own test bundle already links both).  That
only works if every externally visible symbol either carries our prefix or is
genuinely identical in both copies.

Two mechanisms do the prefixing, and between them they cover everything
BoringSSL *names*:

  * C symbols are renamed by `#define BORINGSSL_PREFIX CNIOBoringSSL` plus the
    generated `boringssl_prefix_symbols*.h` macro headers.
  * C++ entities land in `bssl::CNIOBoringSSL::`, because `BSSL_NAMESPACE_BEGIN`
    expands to an inline namespace named after the prefix.

Neither can reach instantiations of *standard library* templates, which live in
namespace std.  Those leak out unprefixed, and that is fine: they are weak
definitions that the linker coalesces, and their bodies depend only on libc++
and the template arguments, so the copies really are interchangeable.

So we check two things.  Rule 1 has no allowlist and is the one that would
actually break a link with a duplicate symbol error.  Rule 2 covers the residual
ODR risk -- a std template instantiated over a BoringSSL type, where the mangled
name is prefix-independent but the body might not be -- and needs a human to
look at anything new, so it is backed by a deliberately tiny file.

Deliberately *not* checked: symbols that are already hidden (private extern /
STV_HIDDEN).  The linker localises those, so they cannot collide.  Filtering
them out is what keeps rule 2's allowlist down to a single line.

Known gap: rule 2 spots BoringSSL types by harvesting struct tags out of the
vendored headers.  A type the harvest misses is a false negative, never a false
failure -- so run with --verbose when bumping BoringSSL and skim the list.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_ROOT = os.path.join(REPO_ROOT, "Sources", "CNIOBoringSSL")
ALLOWED_TYPES_PATH = os.path.join(
    REPO_ROOT, "scripts", "boringssl-unprefixed-types.txt"
)

TARGET = "CNIOBoringSSL"
PREFIX = "CNIOBoringSSL"

# Helpers clang itself emits. Not BoringSSL code, and identical wherever they
# are needed, so they coalesce safely.
COMPILER_RUNTIME = re.compile(
    r"^_*(clang_call_terminate|gxx_personality|gcc_except_table)"
)

# A mangled name is rooted in namespace std when the only things between the _Z
# and the 'St' substitution are mangling decorations: nesting (N), cv/ref
# qualifiers (K, R, O, V), or an RTTI/vtable/guard/local tag (T, I, S, G, L, Z).
# A source name is always length-prefixed, so a leading digit rules std out.
STD_ROOTED = re.compile(r"^_+Z[NKRVOTISGLZ]*St[0-9_]")

# BoringSSL struct tags are overwhelmingly `foo_st`; container types come from
# the DEFINE_/DECLARE_ macros instead of appearing literally.
STRUCT_TAG = re.compile(r"\b[A-Za-z][A-Za-z0-9_]*_st\b")
CONTAINER_TAG = re.compile(r"\b(?:DEFINE|DECLARE)_(?:CONST_)?(STACK|LHASH)_OF\((\w+)\)")


def run(argv):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, cwd=REPO_ROOT
    ).stdout


def object_files(bin_path):
    """Object files for the target, skipping any left behind by deleted sources.

    SwiftPM does not prune objects when a source file disappears, which happens
    every time BoringSSL is re-vendored. Stale objects would show up here as
    phantom symbols, so we keep only those whose source still exists. The build
    directory mirrors the source tree, so `ssl/ssl_lib.cc.o` maps back to
    `Sources/CNIOBoringSSL/ssl/ssl_lib.cc`.
    """
    build_dir = os.path.join(bin_path, TARGET + ".build")
    if not os.path.isdir(build_dir):
        sys.exit(f"error: {build_dir} not found; pass --build or build {TARGET} first")

    objects, stale = [], 0
    for root, _, names in os.walk(build_dir):
        for name in names:
            if not name.endswith(".o"):
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, build_dir)[: -len(".o")]
            if os.path.exists(os.path.join(SOURCE_ROOT, relative)):
                objects.append(path)
            else:
                stale += 1

    if not objects:
        sys.exit(f"error: no object files under {build_dir}")
    if stale:
        print(
            f"note: ignoring {stale} stale object(s) with no matching source",
            flush=True,
        )
    return sorted(objects)


def visible_symbols_macho(objects):
    """Defined symbols with default visibility, from `nm -m`.

    Lines look like:
        0000000000003e94 (__TEXT,__text) weak external __ZNK...
        0000000000002868 (__TEXT,__text) non-external (was a private external) __Z...
        0000000000003e94 (__DATA,__const) weak private external __ZTI...
                         (undefined) external __ZNSt...
    """
    symbols = set()
    for line in run(["nm", "-m"] + objects).splitlines():
        if " external " not in line and not line.endswith(" external"):
            continue
        if "(undefined)" in line:
            continue
        if "non-external" in line or "private external" in line:
            continue
        symbols.add(line.split()[-1])
    return symbols


def visible_symbols_elf(objects, readelf):
    """Defined symbols with default visibility, from `readelf -sW`.

    Columns are: Num, Value, Size, Type, Bind, Vis, Ndx, Name.
    """
    symbols = set()
    for line in run([readelf, "-sW"] + objects).splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        _, _, _, _, bind, vis, ndx, name = fields[:8]
        if bind not in ("GLOBAL", "WEAK") or vis != "DEFAULT" or ndx == "UND":
            continue
        symbols.add(name.split("@")[0])
    return symbols


def visible_symbols(objects):
    if platform.system() == "Darwin":
        if not shutil.which("nm"):
            sys.exit("error: nm not found")
        return visible_symbols_macho(objects)
    for candidate in ("readelf", "llvm-readelf", "eu-readelf"):
        if shutil.which(candidate):
            return visible_symbols_elf(objects, candidate)
    sys.exit(
        "error: need readelf (binutils) to read symbol visibility on this platform"
    )


def boringssl_type_tags():
    """Harvest BoringSSL's struct tags from the vendored source."""
    tags = set()
    for root, _, names in os.walk(SOURCE_ROOT):
        for name in names:
            if not name.endswith((".h", ".cc", ".inc")):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            tags.update(STRUCT_TAG.findall(text))
            for kind, arg in CONTAINER_TAG.findall(text):
                tags.add(f"{kind.lower()}_st_{arg}")
    return tags


def types_mentioned(symbol, tags):
    """Which BoringSSL tags appear as length-prefixed components of `symbol`.

    Itanium mangling spells a source name as `<length><name>`, so we look for
    that exact token. The length digits of a genuine component are never
    preceded by another digit, so the lookbehind stops us matching the tail of a
    longer component's length -- `7x509_st` inside `17x509_store_ctx_st`. We
    deliberately do not anchor the end: a component is followed by more mangling
    characters, which are letters (`P6ssl_stPv`).
    """
    return {
        tag
        for tag in tags
        if re.search(rf"(?<![0-9]){len(tag)}{re.escape(tag)}", symbol)
    }


def allowed_types():
    with open(ALLOWED_TYPES_PATH, encoding="utf-8") as handle:
        return {
            line.strip()
            for line in handle
            if line.strip() and not line.startswith("#")
        }


def demangle(symbols):
    if not symbols or not shutil.which("c++filt"):
        return {s: s for s in symbols}
    # Mach-O prepends an underscore that c++filt does not expect.
    stripped = [s[1:] if s.startswith("__Z") else s for s in symbols]
    out = subprocess.run(
        ["c++filt"], input="\n".join(stripped), capture_output=True, text=True
    ).stdout.splitlines()
    if len(out) != len(symbols):
        return {s: s for s in symbols}
    return dict(zip(symbols, out))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help=f"build {TARGET} first")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="list every unprefixed symbol (useful when bumping BoringSSL)",
    )
    args = parser.parse_args()

    if args.build:
        subprocess.run(
            ["swift", "build", "--target", TARGET], check=True, cwd=REPO_ROOT
        )
    bin_path = run(["swift", "build", "--show-bin-path"]).strip().splitlines()[-1]

    objects = object_files(bin_path)
    symbols = visible_symbols(objects)
    unprefixed = sorted(s for s in symbols if PREFIX not in s)

    print(
        f"{len(objects)} objects, {len(symbols)} visible symbols, "
        f"{len(unprefixed)} unprefixed",
        flush=True,
    )

    # Rule 1: everything unprefixed must be rooted in namespace std.
    not_std = [
        s
        for s in unprefixed
        if not STD_ROOTED.search(s) and not COMPILER_RUNTIME.search(s)
    ]

    # Rule 2: std-rooted symbols may only mention BoringSSL types we have vetted.
    tags = boringssl_type_tags()
    permitted = allowed_types()
    mentions = {}
    for symbol in unprefixed:
        for tag in types_mentioned(symbol, tags) - permitted:
            mentions.setdefault(tag, []).append(symbol)

    if args.verbose:
        names = demangle(unprefixed)
        print("\nunprefixed symbols:")
        for symbol in unprefixed:
            print(f"  {names[symbol]}")

    if not_std:
        names = demangle(not_std)
        print(
            f"\nerror: {len(not_std)} symbol(s) are neither prefixed with "
            f"{PREFIX} nor rooted in namespace std.\nThese will collide with "
            f"another BoringSSL copy at static link time. Extend the prefixing "
            f"to cover them:",
            file=sys.stderr,
        )
        for symbol in not_std:
            print(f"  {symbol}\n    {names[symbol]}", file=sys.stderr)

    if mentions:
        print(
            f"\nerror: {len(mentions)} BoringSSL type(s) appear in unprefixed "
            f"std instantiations and are not vetted in "
            f"{os.path.relpath(ALLOWED_TYPES_PATH, REPO_ROOT)}.\nTwo copies of "
            f"BoringSSL would share one definition of these, so check that the "
            f"generated code does not depend on the type's layout (a pointer or "
            f"reference is fine, by-value storage is not), then add the type to "
            f"that file:",
            file=sys.stderr,
        )
        for tag, examples in sorted(mentions.items()):
            print(f"  {tag} ({len(examples)} symbols), e.g.", file=sys.stderr)
            print(f"    {demangle(examples[:1])[examples[0]]}", file=sys.stderr)

    if not_std or mentions:
        return 1

    print(
        f"ok: prefixing is complete; {len(unprefixed)} unprefixed symbols all "
        f"coalesce safely"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Someone piped us into `head`. Not an error, but sys.exit alone is not
        # enough: stdout's buffer still holds the bytes that failed to write, so
        # the flush during interpreter shutdown hits EPIPE again and CPython
        # prints "Exception ignored ... BrokenPipeError" to stderr. Send that
        # last flush to /dev/null so we exit quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
