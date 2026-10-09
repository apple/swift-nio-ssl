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
the standard library's own namespaces.  Those leak out unprefixed, and that is
fine: they are weak definitions that the linker coalesces, and their bodies
depend only on the standard library and the template arguments, so the copies
really are interchangeable.

So we check two things.  Rule 1 has no allowlist and is the one that would
actually break a link with a duplicate symbol error: anything unprefixed must
belong to the standard library.  Rule 2 covers the residual ODR risk -- a std
template that stores a BoringSSL type *by value*, where the mangled name is
prefix-independent but the layout is baked into the body -- and needs a human to
look at anything new, so it is backed by a deliberately tiny file.

How much leaks out is very much platform-dependent, which is why both rules are
written against mangling structure rather than a list of names.  libc++ marks
nearly all of its internals hidden, so on Darwin about 90 symbols leak.
libstdc++ hides far less and keeps its iterator helpers in __gnu_cxx::, so on
Linux it is several hundred.  Both are safe for the same reason; neither needs
enumerating.

Hidden symbols (private extern / STV_HIDDEN) are included, not skipped.  It is
tempting to assume the linker localises them so they cannot collide, but that is
wrong for how this package is built: SwiftPM compiles the whole dependency tree
to objects and links once, and within a single link the linker still merges weak
hidden definitions across objects.  Visibility only decides whether the survivor
is re-exported from the finished binary.  Only genuinely file-local symbols are
skipped.

A consequence is that the build system does not matter here.  swiftbuild
compiles with hidden visibility and native does not, but since we look at hidden
symbols too, both reach the same verdict; they differ only in the libc++ ABI tag
baked into some mangled names.

Known gap: rule 2 spots BoringSSL types by harvesting struct tags out of the
vendored source.  A type the harvest misses is a false negative, never a false
failure -- so run with --verbose when bumping BoringSSL and skim the list.
"""

import argparse
import glob
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

# Helpers the compiler itself emits. Not BoringSSL code, and identical wherever
# they are needed, so they coalesce safely. `DW.ref.` prefixes the unwinder's
# reference to the personality routine, which GCC emits per object.
COMPILER_RUNTIME = re.compile(
    r"^(DW\.ref\.)?_*(clang_call_terminate|gxx_personality|gcc_except_table)"
)

# libc++ supplies constexpr-friendly overloads of a few C library functions
# (memchr, strchr, ...) in the *global* namespace rather than in std::, selected
# with __attribute__((enable_if)). That attribute mangles as the vendor-extended
# qualifier `Ua9enable_if`, which nothing in BoringSSL uses, so it is a reliable
# fingerprint for "this is standard library code that merely isn't namespaced".
LIBCXX_C_OVERLOAD = re.compile(r"Ua9enable_if")

# Typeinfo and typeinfo-name. For a plain C struct these hold the type's *name*
# and nothing else -- no size, no member offsets -- so two copies emit byte
# identical data and coalescing is safe however the struct is defined. Vtables
# (_ZTV) would encode layout, so they are deliberately not listed here.
RTTI_NAME_ONLY = re.compile(r"^_+Z(TI|TS)")

# Namespaces owned by the C++ standard library implementation. Instantiations
# rooted here are the library's own code, identical in every copy that uses the
# same toolchain, so they coalesce safely. libc++ keeps almost everything in
# std:: and hides most of it; libstdc++ exposes far more and puts its iterator
# helpers in __gnu_cxx::, hence the second and third entries.
STDLIB_ROOTS = frozenset({"std", "__gnu_cxx", "__cxxabiv1"})

# Itanium mangling: `_Z`, then decorations -- nesting (N), cv/ref qualifiers
# (K, R, O, V), RTTI/vtable/guard/local tags (T, I, S, G, L, Z) -- then the
# first name component. `St` is the substitution for std; anything else is
# length-prefixed, so `9__gnu_cxx` is the namespace __gnu_cxx.
FIRST_COMPONENT = re.compile(r"^_+Z[NKRVOTISGLZ]*?(St|(\d+)([A-Za-z_][A-Za-z0-9_]*))")

# Indirection markers. A type reached through one of these is incomplete as far
# as the instantiation is concerned, so the emitted code cannot depend on its
# layout. `KVr` are cv-qualifiers that may sit between the marker and the name.
INDIRECTION = "PRO"
CV_QUALIFIERS = "KVr"

# BoringSSL struct tags are overwhelmingly `foo_st`; container types come from
# the DEFINE_/DECLARE_ macros instead of appearing literally.
STRUCT_TAG = re.compile(r"\b[A-Za-z][A-Za-z0-9_]*_st\b")
CONTAINER_TAG = re.compile(r"\b(?:DEFINE|DECLARE)_(?:CONST_)?(STACK|LHASH)_OF\((\w+)\)")


def stdlib_rooted(symbol):
    """Is this mangled name rooted in a standard library namespace?"""
    match = FIRST_COMPONENT.match(symbol)
    if not match:
        return False
    if match.group(1) == "St":
        return "std" in STDLIB_ROOTS
    length, name = int(match.group(2)), match.group(3)
    return name[:length] in STDLIB_ROOTS and len(name) >= length


def run(argv):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, cwd=REPO_ROOT
    ).stdout


def source_stems():
    """Basenames, minus extension, of every compiled source in the target."""
    stems = set()
    for root, _, names in os.walk(SOURCE_ROOT):
        for name in names:
            if name.endswith((".cc", ".c", ".S")):
                stems.add(os.path.splitext(name)[0])
    return stems


def target_build_dirs(parent):
    """Directories under `parent` that could hold this target's objects.

    Swift 6.4's swiftbuild renamed the target directory to
    `CNIOBoringSSL-t.build` and left a `CNIOBoringSSL.build` behind containing
    only .d/.dia files, so match both spellings. Callers pick between them by
    looking for actual object files, not by name.
    """
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        return []
    pattern = re.compile(rf"^{re.escape(TARGET)}(?:-\w+)?\.build$")
    return [
        os.path.join(parent, name)
        for name in names
        if pattern.match(name) and os.path.isdir(os.path.join(parent, name))
    ]


def candidate_dirs(bin_path):
    """Candidate intermediates directories, as (path, layout) pairs.

    `--show-bin-path` reports where *products* land, which is not where the
    per-source objects live, and the relationship between the two differs by
    build system -- and by toolchain version:

      native      .build/<triple>/<config>/CNIOBoringSSL.build/...
                  (same directory as the products, so bin_path works directly)

      swiftbuild  .build/out/Products/<Config>              <- bin_path
                  .build/out/Intermediates.noindex/<package>.build/<Config>/
                      CNIOBoringSSL{,-t}.build/Objects-normal/<arch>/...

    `<Config>` is whatever bin_path ends with, which is `Debug` on Darwin and
    `Debug-linux-aarch64` on Linux, so take it from the path rather than
    assuming.
    """
    candidates = [(path, "native") for path in target_build_dirs(bin_path)]

    products_dir, config = os.path.split(bin_path.rstrip(os.sep))
    if os.path.basename(products_dir) == "Products":
        intermediates = os.path.join(
            os.path.dirname(products_dir), "Intermediates.noindex"
        )
        try:
            packages = sorted(
                name for name in os.listdir(intermediates) if name.endswith(".build")
            )
        except OSError:
            packages = []
        for package in packages:
            parent = os.path.join(intermediates, package, config)
            candidates.extend(
                (path, "swiftbuild") for path in target_build_dirs(parent)
            )
    return candidates


def objects_in(build_dir, stems):
    """Objects under `build_dir` whose source still exists, and a stale count.

    Neither build system prunes objects when a source file disappears, which
    happens every time BoringSSL is re-vendored. Stale objects would show up
    here as phantom symbols, so keep only those whose source still exists.

    Object names differ between build systems -- native mirrors the source tree
    and keeps the extension (`ssl/ssl_lib.cc.o`), swiftbuild flattens into one
    directory and drops it (`ssl_lib.o`) -- so match on the basename stem, which
    is unique across this source tree.
    """
    objects, stale = [], 0
    for root, _, names in os.walk(build_dir):
        for name in names:
            if not name.endswith(".o"):
                continue
            stem = os.path.splitext(os.path.splitext(name)[0])[0]
            if stem in stems:
                objects.append(os.path.join(root, name))
            else:
                stale += 1
    return objects, stale


def object_files(bin_path):
    """Object files for the target, from whichever candidate actually has them."""
    stems = source_stems()
    candidates = candidate_dirs(bin_path)

    for build_dir, layout in candidates:
        objects, stale = objects_in(build_dir, stems)
        if not objects:
            continue
        print(
            f"objects from {os.path.relpath(build_dir, REPO_ROOT)} ({layout})",
            flush=True,
        )
        if stale:
            print(
                f"note: ignoring {stale} stale object(s) with no matching source",
                flush=True,
            )
        return sorted(objects)

    found = sorted(
        os.path.relpath(path, REPO_ROOT)
        for path in glob.glob(
            os.path.join(REPO_ROOT, ".build", "**", TARGET + "*.build"), recursive=True
        )
    )
    message = f"error: found no object files for {TARGET}.\n"
    if candidates:
        message += "Checked (all empty of .o):\n"
        message += "".join(f"  {path}\n" for path, _ in candidates)
    else:
        message += f"No {TARGET} build directory next to {bin_path}.\n"
    if found:
        message += "Build directories that do exist:\n"
        message += "".join(f"  {path}\n" for path in found)
        message += "Pass the --build-system you built with, or --build to build here.\n"
    else:
        message += f"Build {TARGET} first, or pass --build.\n"
    sys.exit(message)


def visible_symbols_macho(objects):
    """Defined symbols that can take part in coalescing, from `nm -m`.

    Lines look like:
        0000000000003e94 (__TEXT,__text) weak external __ZNK...
        0000000000002868 (__TEXT,__text) non-external (was a private external) __Z...
        0000000000003e94 (__DATA,__const) weak private external __ZTI...
                         (undefined) external __ZNSt...

    Hidden symbols (`private external`) are *included*. Visibility only decides
    whether the survivor is re-exported from the finished binary; within a
    single link the linker still merges weak hidden definitions across objects,
    so a hidden symbol can silently unify two copies' differing bodies just as
    an exported one can. Only `non-external` is skipped: those are file-local
    from the start and cannot be merged with anything.
    """
    symbols = set()
    for line in run(["nm", "-m"] + objects).splitlines():
        if "(undefined)" in line or "external" not in line:
            continue
        if "non-external" in line:
            continue
        symbols.add(line.split()[-1])
    return symbols


def visible_symbols_elf(objects, readelf):
    """Defined symbols that can take part in coalescing, from `readelf -sW`.

    Columns are: Num, Value, Size, Type, Bind, Vis, Ndx, Name.

    STV_HIDDEN symbols are *included*, for the same reason as on Mach-O: within
    a single link the linker still merges weak hidden definitions. Only LOCAL
    binding is skipped, since those cannot be merged with anything.
    """
    symbols = set()
    for line in run([readelf, "-sW"] + objects).splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        _, _, _, _, bind, _vis, ndx, name = fields[:8]
        if bind not in ("GLOBAL", "WEAK") or ndx == "UND":
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
    """BoringSSL tags that `symbol` stores *by value*.

    Itanium mangling spells a source name as `<length><name>`, so look for that
    exact token. The length digits of a genuine component are never preceded by
    another digit, which rules out matching the tail of a longer component's
    length -- `7x509_st` inside `17x509_store_ctx_st`.

    Only by-value uses matter. `std::variant<..., int (*)(ssl_st *, void *)>` or
    `std::tuple<x509_st *>` mangle the same in every BoringSSL copy, but the
    pointee is incomplete to the instantiation: it only ever moves
    pointer-sized values, so the emitted code is byte-identical whatever the
    struct looks like, and coalescing is safe. Storing one by value would make
    size, alignment and member offsets part of the generated code while the
    symbol name stayed the same -- that is the real ODR hazard, so that is what
    we report. Anything we cannot classify counts as by value: fail closed.
    """
    hits = set()
    for tag in tags:
        token = f"{len(tag)}{tag}"
        for match in re.finditer(re.escape(token), symbol):
            start = match.start()
            if start > 0 and symbol[start - 1].isdigit():
                continue
            index = start - 1
            while index >= 0 and symbol[index] in CV_QUALIFIERS:
                index -= 1
            if index >= 0 and symbol[index] in INDIRECTION:
                continue
            hits.add(tag)
            break
    return hits


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


def build_system_args(requested):
    """`--build-system X`, or nothing if this toolchain has no such flag.

    The flag postdates our minimum toolchain. Older SwiftPM only has the native
    build system, so dropping it there still gets the layout we asked for.
    """
    if not requested:
        return []
    if "--build-system" not in run(["swift", "build", "--help"]):
        print(
            f"note: this swift build has no --build-system; ignoring "
            f"--build-system {requested}",
            flush=True,
        )
        return []
    return ["--build-system", requested]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help=f"build {TARGET} first")
    parser.add_argument(
        "--build-system",
        choices=("native", "swiftbuild", "xcode"),
        help="forwarded to swift build; use the same one you build with",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="list every unprefixed symbol (useful when bumping BoringSSL)",
    )
    args = parser.parse_args()

    # Keep the build and the lookup on the same build system, or they disagree
    # about where the objects are.
    system = build_system_args(args.build_system)

    if args.build:
        build = subprocess.run(
            ["swift", "build", *system, "--target", TARGET], cwd=REPO_ROOT
        )
        if build.returncode != 0:
            sys.exit(f"error: swift build --target {TARGET} failed; see above")
    bin_path = (
        run(["swift", "build", *system, "--show-bin-path"]).strip().splitlines()[-1]
    )

    objects = object_files(bin_path)
    symbols = visible_symbols(objects)
    unprefixed = sorted(s for s in symbols if PREFIX not in s)

    print(
        f"{len(objects)} objects, {len(symbols)} visible symbols, "
        f"{len(unprefixed)} unprefixed",
        flush=True,
    )

    # Rule 1: everything unprefixed must belong to the standard library or the
    # compiler runtime, or be data that carries no layout (typeinfo).
    not_std = [
        s
        for s in unprefixed
        if not stdlib_rooted(s)
        and not COMPILER_RUNTIME.search(s)
        and not LIBCXX_C_OVERLOAD.search(s)
        and not RTTI_NAME_ONLY.match(s)
    ]

    # Rule 2: those may only store BoringSSL types by value if we have vetted it.
    tags = boringssl_type_tags()
    permitted = allowed_types()
    mentions = {}
    for symbol in unprefixed:
        if RTTI_NAME_ONLY.match(symbol):
            continue
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
