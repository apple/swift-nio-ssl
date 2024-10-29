#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

# shellcheck source=IntegrationTests/tests_01_general/defines.sh
source defines.sh

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "No need to run execstack on Darwin"
    exit 0
fi

swift build -c debug
swift build -c release

DEBUG_SERVER_PATH="$(swift build --show-bin-path)/NIOTLSServer"
RELEASE_SERVER_PATH="$(swift build --show-bin-path -c release)/NIOTLSServer"

results=$(execstack "$DEBUG_SERVER_PATH" "$RELEASE_SERVER_PATH")
count=$(echo "$results" | grep -c '^X' || true)
if [ "$count" -ne 0 ]; then
    exit 1
else
    exit 0
fi
