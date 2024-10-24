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

swift build

# Generate a self-signed certificate.

# shellcheck disable=SC2154 # Provided by framework
cat << EOF > "$tmp/openssl.cnf"
[ req ]
distinguished_name = subject
req_extensions = req_ext
x509_extensions = x509_ext

[ subject ]
countryName         = Country Name (2 letter code)
countryName_default     = US

stateOrProvinceName     = State or Province Name (full name)
stateOrProvinceName_default = NY

localityName            = Locality Name (eg, city)
localityName_default        = New York

organizationName         = Organization Name (eg, company)
organizationName_default    = Example, LLC

[ req_ext ]

basicConstraints = CA:FALSE

[ x509_ext ]
subjectKeyIdentifier = hash
subjectAltName = @alternate_names

[ alternate_names ]
DNS.1 = localhost
EOF


openssl req -new -newkey rsa:4096 -days 365 -nodes -config "$tmp/openssl.cnf" -x509 \
    -subj "/C=US/ST=NJ/L=Wall/O=NIO/CN=localhost" \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem"

expect -c "
          spawn openssl s_server -no_tls1_3 -cert \"$tmp/cert.pem\" -key \"$tmp/key.pem\"
          set serverspawn \$spawn_id
          expect {
              \"ACCEPT\" {
              }
              timeout {
                  exit 1
              }
          }

          spawn $(client_path) http://localhost:4433/get \"$tmp/cert.pem\" \"$tmp/key.pem\" \"$tmp/cert.pem\"
          set spawn_id \$serverspawn

          expect {
              \"close\\r\\r\" {
              }
              timeout {
                  exit 2
              }
          }
          send  \"R\r\"
          expect {
              \"Read BLOCK\\r\" {
              }
              timeout {
                  exit 3
              }
          }
          "

