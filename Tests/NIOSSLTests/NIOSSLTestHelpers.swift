//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
@_implementationOnly import CNIOBoringSSL
import NIOCore
import NIOEmbedded
@testable import NIOSSL

let samplePemCert = """
-----BEGIN CERTIFICATE-----
MIIGGzCCBAOgAwIBAgIJAJ/X0Fo0ynmEMA0GCSqGSIb3DQEBCwUAMIGjMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5z
b2t5bzEuMCwGA1UECgwlU2FuIEZyYW5zb2t5byBJbnN0aXR1dGUgb2YgVGVjaG5v
bG9neTEVMBMGA1UECwwMUm9ib3RpY3MgTGFiMSAwHgYDVQQDDBdyb2JvdHMuc2Fu
ZnJhbnNva3lvLmVkdTAeFw0xNzEwMTYyMTAxMDJaFw00NzEwMDkyMTAxMDJaMIGj
MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2Fu
IEZyYW5zb2t5bzEuMCwGA1UECgwlU2FuIEZyYW5zb2t5byBJbnN0aXR1dGUgb2Yg
VGVjaG5vbG9neTEVMBMGA1UECwwMUm9ib3RpY3MgTGFiMSAwHgYDVQQDDBdyb2Jv
dHMuc2FuZnJhbnNva3lvLmVkdTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAO9rzJOOE8cmsIqAJMCrHDxkBAMgZhMsJ863MnWtVz5JIJK6CKI/Nu26tEzo
kHy3EI9565RwikvauheMsWaTFA4PD/P+s1DtxRCGIcK5x+SoTN7Drn5ZueoJNZRf
TYuN+gwyhprzrZrYjXpvEVPYuSIeUqK5XGrTyFA2uGj9wY3f9IF4rd7JT0ewRb1U
8OcR7xQbXKGjkY4iJE1TyfmIsBZboKaG/aYa9KbnWyTkDssaELWUIKrjwwuPgVgS
vlAYmo12MlsGEzkO9z78jvFmhUOsaEldM8Ua2AhOKW0oSYgauVuro/Ap/o5zn8PD
IDapl9g+5vjN2LucqX2a9utoFvxSKXT4NvfpL9fJvzdBNMM4xpqtHIkV0fkiMbWk
EW2FFlOXKnIJV8wT4a9iduuIDMg8O7oc+gt9pG9MHTWthXm4S29DARTqfZ48bW77
z8RrEURV03o05b/twuAJSRyyOCUi61yMo3YNytebjY2W3Pxqpq+YmT5qhqBZDLlT
LMptuFdISv6SQgg7JoFHGMWRXUavMj/sn5qZD4pQyZToHJ2Vtg5W/MI1pKwc3oKD
6M3/7Gf35r92V/ox6XT7+fnEsAH8AtQiZJkEbvzJ5lpUihSIaV3a/S+jnk7Lw8Tp
vjtpfjOg+wBblc38Oa9tk2WdXwYDbnvbeL26WmyHwQTUBi1jAgMBAAGjUDBOMB0G
A1UdDgQWBBToPRmTBQEF5F5LcPiUI5qBNPBU+DAfBgNVHSMEGDAWgBToPRmTBQEF
5F5LcPiUI5qBNPBU+DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCY
gxM5lufF2lTB9sH0s1E1VTERv37qoapNP+aw06oZkAD67QOTXFzbsM3JU1diY6rV
Y0g9CLzRO7gZY+kmi1WWnsYiMMSIGjIfsB8S+ot43LME+AJXPVeDZQnoZ6KQ/9r+
71Umi4AKLoZ9dInyUIM3EHg9pg5B0eEINrh4J+OPGtlC3NMiWxdmIkZwzfXa+64Z
8k5aX5piMTI+9BQSMWw5l7tFT/PISuI8b/Ln4IUBXKA0xkONXVnjPOmS0h7MBoc2
EipChDKnK+Mtm9GQewOCKdS2nsrCndGkIBnUix4ConUYIoywVzWGMD+9OzKNg76d
O6A7MxdjEdKhf1JDvklxInntDUDTlSFL4iEFELwyRseoTzj8vJE+cL6h6ClasYQ6
p0EeL3UpICYerfIvPhohftCivCH3k7Q1BSf0fq73cQ55nrFAHrqqYjD7HBeBS9hn
3L6bz9Eo6U9cuxX42k3l1N44BmgcDPin0+CRTirEmahUMb3gmvoSZqQ3Cz86GkIg
7cNJosc9NyevQlU9SX3ptEbv33tZtlB5GwgZ2hiGBTY0C3HaVFjLpQiSS5ygZLgI
/+AKtah7sTHIAtpUH1ZZEgKPl1Hg6J4x/dBkuk3wxPommNHaYaHREXF+fHMhBrSi
yH8agBmmECpa21SVnr7vrL+KSqfuF+GxwjSNsSR4SA==
-----END CERTIFICATE-----
"""

let samplePemKey = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

let sampleECPemKey = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMJZj2Qw9NGv83izxbgRr5xRvb0RHymOfl5hDJ/RPI2GoAoGCCqGSM49
AwEHoUQDQgAEc5zHoemKB93GfO9MA/vLYEiYMtV3UWDIV88M/TP59R0dKIuPS2Dw
EeAoz1vgyHNpgE73eYX8NII6U11Xv8Lmgg==
-----END EC PRIVATE KEY-----
"""

let samplePemRSAEncryptedKey = """
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,701BA8806DAD9F13E63F41109F51B2AD

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
-----END RSA PRIVATE KEY-----
"""

let samplePKCS8PemPrivateKey = """
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIShGta1Mpj/QCAggA
MBQGCCqGSIb3DQMHBAjQbLTPjvMqpwSCBMh8omeDIM0ceuoiEhaepFqbst/jUwYh
m1pzLokTph0GS/81vmTDr9U7uI9rHiFbACRRMQBH/cCkZFUN2Jo3pJXA4q3RvGsh
4UIaWiP+SNkzKR54QcuWRzYoQs/YH8VickNp2per3zQ9R0Regx1ZaHSCk3cFRFy3
4sJtgoquwJYD2vUdQvhwcuF2Syl/VCpaQ0+KtfBqJ+4YLJPQcsL+OKLlaWFY0ivO
2oSVCg3QJrVbS8TDnrIgeL8MNhyVHQbuSyh2MlXKcjiKlJHdHXSlYSINgpUsc/Eg
cTSgod0JXvjbExrtBx2mODwM5hzDkGpdub+TptXinQg3FQjUKhBh/+wrP0HoKBcn
UFE1emd3n1s0MFN28uSN3OcX3833Lt4KAnxF4xaPfWEAk/2yuukiUqKU+K9cEhNX
V1arxKq8RLB7n7o6YFt3xuVgAJYWDk6nyr/0I2LgFj2Jz/C2v+YBFYGUcQUKgHQw
OLzzZnCrPj8JIP2cUqagZrW7JOoMsFCtroJptImaqhsm/4i3tyf2uoUWglZN8DVE
WbNbnAr5KZSl9U1/sNuEesixIWd+RrJC/l0tNmScCvJifL9WrJnccOI83EAkmz/+
W8UpcPCscAmAdOcjFQl8T37xHGxwVcvh8LyaoacBqQCYiZzO/M6bA2YuBYVpkk4v
DFXMmy2SaHGGhGHDmyn4uuzykGCOn1ZN92eT6PXZCmHz0/QCH6RIGx2cK5frfhUP
icU30GnK1jRv8QFHVx9IZQpHbALRgSNMbtF8EqWmONUIs9wQIQtEMZ2AYwq8gKL2
9Cwk2SkqO0Y8dbE/lw+iBA37/NO7KiSLB/Mpq0/zX5SfBVcGZAVzGKiyeOW5sKcI
pSOTTv5jLkoEnels2f0jsPM7aMjG+ys6wveL0tDhfKSbtjyC8Zw/eXpK9AHGW8Hr
xM7hwTkQpznyt/NUIDmjrDHg7n6O9sp7KWduP1L9bYC/n5Dj2gnxHj6FFTpMqmm7
Q6GEj/dttmqvSYeG93heWqoS/j6j45dppoKG/3vU9UWODStcc3y66WJ2ULEY0/CF
IiBd33GJgIKUJlrMGwUSAPxH2wklF3VwWFVXMnLbqpggaWlVxzVnvGjnzoHm3AW6
hWCMnvsP/pYVBMpaKKdPF6PCW1yQXjTbA67gxpGECoin2Bu/rp+t0GeVmgTcCS9a
Y2Su4cpwCD1ngIrdodWhVVJSObApRdn3SDI2xOZUgZPVT52AtEMPQ3R5eoIOfLI6
CPC7cYl2JDmMkKGLaSom1zZpCoXtPTkxDAIpaG4ofT6pIDibCSywllL1KeeVw4WX
Cr2b/BS5TZNFyPzdrMaN5og6hNkbyca73SyEADnJtHTQc6mi/Q93al4TI3RYaVpk
KWwIW4kZE/p5pONeZDNNt7dKrgkjaTylNpM9jdnBL3hU5Fxr4I6a6+IBWQC03EwC
o2zT+g6YmVkod050GMv0V60npTpbOpWIamzB+q3GMMkU9NNyw8xH7RkNS78eWLVv
niWQmWlbkzLEf5PT264+c4w9IkE8aUKY2V8Ev2k1FXZcLdfw3G5yVzrjXoAwFUaY
xnOAdO/QLMtD55Kn+jzV6dCXmyZQkBJAMLBF5xEX9DcnXCptZ2Asgvxa4EpO7jzX
v5o=
-----END ENCRYPTED PRIVATE KEY-----
"""

/// A CA that expired a while ago.
let sampleExpiredCA = """
-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIUTSNLkfg8YiYSq+fnrXP25txgCkUwDQYJKoZIhvcNAQEL
BQAwIjEgMB4GA1UEAwwXYmFkQ2VydGlmaWNhdGVBdXRob3JpdHkwHhcNMTkwODA5
MTk1MTExWhcNMTkxMTE3MTk1MTExWjAiMSAwHgYDVQQDDBdiYWRDZXJ0aWZpY2F0
ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKqWcbgw
TFX14tKxUMIrla9Y0aLddlnnTDqsxtxJ7dSjE4+OBkVBslCq4WtjgaeubdHkTCtc
GRVeOpXVcEyznGBGW5k/5gCkmaGPe8jI4+caavtXnoTdPU91ukYkZkBXzCgycVS8
kQxyPwvTDUOfHQ3VqUfc2LMTXQYU3vzyrPzq7XAWgZR9d5lOtB9tpGnxCRP8GOFO
KHa3KroiRxJb2cReJsayJWx713pje5lPKtSKP0iYICR2kYgtP+8Y3wPzcLzPRM9u
6a0olO6PFFWdPNRtivObCr5Y3Cy0P8i2ZSyOO2c6cn0ksLmCe/qrRX9HKx7TrmEu
7Rs+ql6liiyrQ7ECAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAWSCh35Fk5Td+8uV3oe+K+IPbTrhtNmrwC42sGw/mpQC56zNjlDt9
jBZVZbu5iAwO/nrtn+JpCSA3ADugjisQKQdELb/ogaCnIu2vY/fjHv7a9/tYoYc2
i/rtcXIQdhSrniZuVnKG1Keu5qohKIP1ne4TAxADTlzl3Dx7QH/32hUBlJFwYiDQ
JIuZD9LM5Ic9jtrsfTN79tNPM3eHofWUdKyUk9fTrM7/28kSERLJJz/RcXDMP85z
5Y0zZar+qh+9A6kYy/xcaFVOX0bDsuArBA6d/n0skqJN8gylOvdsnpeJRrXxOSSE
dcvafu1dqy0zZdFMSzymwRnprqgdFYC1xw==
-----END CERTIFICATE-----
"""

/// An intermediate signed by the above CA.
let sampleIntermediateCA = """
-----BEGIN CERTIFICATE-----
MIIC3DCCAcSgAwIBAgIUDK9fkCTocM8Yu3csdNcm86ahG4IwDQYJKoZIhvcNAQEL
BQAwIjEgMB4GA1UEAwwXYmFkQ2VydGlmaWNhdGVBdXRob3JpdHkwHhcNMTkxMTE2
MTk1MTExWhcNMzAwNjAyMTk1MTExWjAZMRcwFQYDVQQDDA5pbnRlcm1lZGlhdGVD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdj2KDFRR6Es/RpN+07
q4IiQMoLVcDu/CoxCJSteNuNShmScfyqG4e6AFDOKxjv2U2NHWmhVbBYN7b9jStf
uZBpvz4/JY4+mVfGASL7mBkcsTLzNG+7rmQ0Oi271KL5WlDmw6DUMIFNvYSy0q9y
MFS5qSYJh4JnXXtdxkGIjDmrWy1hCRzIGCpDZXvNjnhJDphgH3Ss+PR7wTJZXRiJ
uoO4plWWl3JsRIRoyuL7K2CeWrR7CvIEThTF/D2P/7odf+CNz//46lC83b5eKdIA
GD+RECQaA1YFygAbvEln+za5AjnH11Y310zvzAb1gCxGuxNaABNKhYLcDpDL/Mcd
Il0CAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
X4D5jVygEJyp6Ub/Yao9miF/vZW0bep00gOzHVJ8i6y1Qjn9ieVyrX9l6V8ZNwQU
wrAkse99WoI94LT8QLWlAlDB7S0IS8IK7gkt+06pSbrhW5GJtEQJjug84DkOVqOm
JSCupM2BEiHVQPYerF+sJ7I/4eENkafVn0zXSL9SEh9fPXBYJKiCYIxKWmGF3KOp
KG5Y1W9sWz5NaatoL1kHFGDeuDWLwXJ8WZuNrtJNBe1iQ8yvuO1STRzjtq2iTDk3
TCYZoKnV3ui38BJn7libgUsN3lHD4yKdrw5LNeyjrYOZ5oFhe4QBQv0ZA+wUR+h7
1A4gDvFcIkbYSywqlirBQg==
-----END CERTIFICATE-----
"""

/// The intermediate above, self-signed, as a root
let sampleIntermediateAsRootCA = """
-----BEGIN CERTIFICATE-----
MIIC0zCCAbugAwIBAgIUDK9fkCTocM8Yu3csdNcm86ahG4IwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlQ0EwHhcNMTkxMTE2MTk1MTExWhcN
MzAwNjAyMTk1MTExWjAZMRcwFQYDVQQDDA5pbnRlcm1lZGlhdGVDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALdj2KDFRR6Es/RpN+07q4IiQMoLVcDu
/CoxCJSteNuNShmScfyqG4e6AFDOKxjv2U2NHWmhVbBYN7b9jStfuZBpvz4/JY4+
mVfGASL7mBkcsTLzNG+7rmQ0Oi271KL5WlDmw6DUMIFNvYSy0q9yMFS5qSYJh4Jn
XXtdxkGIjDmrWy1hCRzIGCpDZXvNjnhJDphgH3Ss+PR7wTJZXRiJuoO4plWWl3Js
RIRoyuL7K2CeWrR7CvIEThTF/D2P/7odf+CNz//46lC83b5eKdIAGD+RECQaA1YF
ygAbvEln+za5AjnH11Y310zvzAb1gCxGuxNaABNKhYLcDpDL/McdIl0CAwEAAaMT
MBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWervzZUKKDEb
O9nXiJckFEBmCOlQuQ6O6+hVyRLAugtPDUyesCUDqoLF2wmMKNRM322gJKaWShaM
ueBrXHIx+ERXKJsgFic8b2m/v+VT16aAVPvQCLmZBpWR2ICqgNTpUzoDXqIZk/9l
ZkJZMaS9kiQmEPeTDH2O8acO9TjqmQbdZa+q6kBWBnNzLPOu5ziEdKrh7rNzikUw
qe0yKxavA5L8l8uWumGC8L6GE7ie7X8oMLwaLXFXt2TG9ZENrVQ0xcLSKTBAF2yL
4lqh2YnpZhntnCtv9Qvx81Asp2+6YfocAe9IKNIA534R2FgoZwt24SokDBhfg49d
2fV7ZO/cqQ==
-----END CERTIFICATE-----
"""

/// A client signed by the intermediate.
let sampleClientOfIntermediateCA = """
-----BEGIN CERTIFICATE-----
MIIC4TCCAcmgAwIBAgIUFJCxfytdLl/FpvlUqwJbztiALjcwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlQ0EwHhcNMTkxMTE2MTk1MTExWhcN
MzAwNTI4MTk1MTExWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDS9XBpPYlP3ToaYKmWaqhXd4lnLSvjReuknE9I
UmvFBoPTyGRU2UNv8N9tFT3xMOX2DrGOn7eVqXBXOvKYRB8+q3CIsh3F/5smdNKQ
PfsL2tFL4d2lvrZ+2GOr2yRtPm9nH0N2wrmJi6GtR1J+x2Uvm7EoHvk3Ujbo77fB
HvFauvwA3GsFT10J+f5buPcNW0rdpo+ASMfMpfBMsr0Ucy1ys9XM/ehCMeWMiX/d
d+fxqmOtl1tGyw4/Bbub5uf/HkiJStbKSCMgs7E4VgVhqFMu6jpeMlADXgDeOKEa
rW+Ds8eb3TkdIlYE2nmwxvdOPeW3AgChkE5RCRYW0aALTwEbAgMBAAGjJjAkMAwG
A1UdEwEB/wQCMAAwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUA
A4IBAQBarG3HrdOULNMGfY/UrSoc2qCQoK33SxM43ecFSXsDbPXLOZHp9iQmib1f
uKy2m4VVkxtxYrQ2i7bueqgRt91rM7hHR8+uopj/BdNYFZfIik+VNFoyKJeATYcx
FRjjAAoMpVYdAJXvtckNix8mlAdan5VNL1AsHYum25BjClQEy+kHM1i3bDLOIiDB
dKMwvI/1ZnUgrMFnAvK8U8WxbxVxij8IeloW+YgjOYXqzjCysVh3L7HkI3AOi6yw
eMNi5idG30y1NnTJWTSWzwR4UcoeLFdzMAmAxo5IVJBYnngcLTEkfofGFC9k2ODI
XANkLW5BKAnSmOQUBrExL4yAj5jt
-----END CERTIFICATE-----
"""

/// The key for the above cert.
let sampleKeyForCertificateOfClientOfIntermediateCA = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDS9XBpPYlP3Toa
YKmWaqhXd4lnLSvjReuknE9IUmvFBoPTyGRU2UNv8N9tFT3xMOX2DrGOn7eVqXBX
OvKYRB8+q3CIsh3F/5smdNKQPfsL2tFL4d2lvrZ+2GOr2yRtPm9nH0N2wrmJi6Gt
R1J+x2Uvm7EoHvk3Ujbo77fBHvFauvwA3GsFT10J+f5buPcNW0rdpo+ASMfMpfBM
sr0Ucy1ys9XM/ehCMeWMiX/dd+fxqmOtl1tGyw4/Bbub5uf/HkiJStbKSCMgs7E4
VgVhqFMu6jpeMlADXgDeOKEarW+Ds8eb3TkdIlYE2nmwxvdOPeW3AgChkE5RCRYW
0aALTwEbAgMBAAECggEBAIzYFxv8XK+4iPFRdggZ35i+EzuSegm8Be6Z+YjUlmUt
y1fbI7lOcOrMy669juR3/CCCgOMzGVPPk1R547vrR10FAxYQrTYjSIetWWO6LeEl
T7U08FGXeapIeIslvTU+iQw1YEprCYqecewJgTdpktHtRaL+wu6/ci+k1G8YZJVo
qPmkSJigrEppm8ciXjvae+89jgUSEUmumI7A+LwiD2qr1GjGMg01TvKJ3jVrU0yq
cGP58zAY/W1DcenJm26bpirE82Wnesosv3hQf2LBMGBMyVp6ErNzITSNN1fUSfyB
231DlGDor9oopfGfk9ApDUUVNXfFUv6ODnCSGBcdUkkCgYEA8snNvwok8IjbXzeG
zdDVUCVLX/o/vrFQg0KmktTArklLe7vAgcbmCp5TbdZKnpHam2KNu6ucgla5ZchV
5vHbAdAhhvZFnYEaDPlpvueVT2jLWZHvsld17vfy7PVpZBwJSa2SQL4aC5sk+Bsn
5LbSE4OL2o0KLQr6+BOAa9soVw8CgYEA3nA6u4Pxdhlf4UGo1fMWFbeXvU6myBs2
JXiAPEM/9wKiGS3LOseqBzLBAoiWND9J7ynDJ+w5uuezwJP6MZImj+J0kbXEm0vy
3iUBGBQvj1FJLN+wJx1QEzZBa+rslqX7vE+YsByJwfffqonGwXpj94Qxf6HMMDea
fRuHxqAjVTUCgYBsXe7bymdahXuFMH+W9hOARmUyXbx+HR7Wt7Up7JRkNorem5r9
Ug3zx19tsyxzQp7UpFSm455j/tmZuKW/A0zBrmiImPvRpYI/MEQm1a8rVpcNT7ox
XCBjnYBsi82SxYDPxg11oGR3sbP6mgRgbcmutBSEZFeaa0BB4lJ70cJbuQKBgQDE
a1gBo3ZB8hAvafp7yqby0GbmnKA7zYOXvPuHu16tcR7QmxZ9tjgXGSNEaHYydryD
u14AT+F+gQHCiSkCQutYXQDQdjDBbWRt80EvEQwaQw4Z2QDE2WaPQHaupAj80l8j
nynWQa0HoilYf0cKLFhABfRrnuUeossBtKDFrTzmDQKBgH2uBQ2v0hV3EW7u2wdy
y7V9lkY+GDm51P1GWAH5c0BBZp3iAW1IBNzbUB8wXVJmhYPWO5Mh7wCAnr18HEZz
OjJVhqRxwhY4NEUsyI86Xxb7rV23HAM6laDItQ/bPlR+b7py5GWCH/DRhhZjHuta
yVOAYA18BnJi7O7Cwd6krmQd
-----END PRIVATE KEY-----
"""

let sampleDerCertSPKI = Array(Data(base64Encoded: """
'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA72vMk44TxyawioAkwKscPGQEAyBmEywnzrcyda1XPkkgkroIoj827bq0TOiQfLcQj3nrlHCKS9q6F4yxZpMUDg8P8/6zUO3FEIYhwrnH5KhM3sOuflm56gk1lF9Ni436DDKGmvOtmtiNem8RU9i5Ih5SorlcatPIUDa4aP3Bjd/0gXit3slPR7BFvVTw5xHvFBtcoaORjiIkTVPJ+YiwFlugpob9phr0pudbJOQOyxoQtZQgquPDC4+BWBK+UBiajXYyWwYTOQ73PvyO8WaFQ6xoSV0zxRrYCE4pbShJiBq5W6uj8Cn+jnOfw8MgNqmX2D7m+M3Yu5ypfZr262gW/FIpdPg29+kv18m/N0E0wzjGmq0ciRXR+SIxtaQRbYUWU5cqcglXzBPhr2J264gMyDw7uhz6C32kb0wdNa2FebhLb0MBFOp9njxtbvvPxGsRRFXTejTlv+3C4AlJHLI4JSLrXIyjdg3K15uNjZbc/Gqmr5iZPmqGoFkMuVMsym24V0hK/pJCCDsmgUcYxZFdRq8yP+yfmpkPilDJlOgcnZW2Dlb8wjWkrBzegoPozf/sZ/fmv3ZX+jHpdPv5+cSwAfwC1CJkmQRu/MnmWlSKFIhpXdr9L6OeTsvDxOm+O2l+M6D7AFuVzfw5r22TZZ1fBgNue9t4vbpabIfBBNQGLWMCAwEAAQ=='
""", options: .ignoreUnknownCharacters)!)

// Custom Root for the certificates below.
// For example the following two certificates were issued from customCARoot:
// 1. leafCertificateForTLSIssuedFromCustomCARoot (Used for TLS)
// 2. leafCertificateForClientAuthenticationIssuedFromCustomCARoot (Used for client authentication)
//    The client authentication certificate contains the Extension for  Client Authentication.
//    Which is required for testing with the CertificateVerification case of .fullVerification.
//
// The certs from the custom root expire once a year, so here are the instructions
// for when they expire again around August 14, 2024:
//
// 1. New custom CA:
// - openssl genpkey -algorithm RSA -out ca_key.pem
// - openssl req -x509 -new -key ca_key.pem -sha256 -days 1024 -out ca.pem
//
// 2. New server cert:
// - openssl genpkey -algorithm RSA -out server_key.pem
// - openssl req -new -key server_key.pem -out server.csr
// - openssl x509 -req -in server.csr -CA ca.pem -CAkey ca_key.pem -CAcreateserial -out server.pem -days 365 -sha256
//
// 3. New client cert:
// - openssl genpkey -algorithm RSA -out client_key.pem
// - now create a file called client_ext.cnf with the contents:
// ```
// [ v3_req ]
// # Extensions for client authentication
// extendedKeyUsage = clientAuth
// ```
// - openssl req -new -key client_key.pem -out client.csr
// - openssl x509 -req -in client.csr -CA ca.pem -CAkey ca_key.pem -CAcreateserial -out client.pem -days 365 -sha256 -extfile client_ext.cnf -extensions v3_req
//
// Then, copy the contents of the files into the literal strings below.
let customCARoot = """
-----BEGIN CERTIFICATE-----
MIICrjCCAZYCCQDFInBpelZ7dzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5l
eGFtcGxlLWNhLmNvbTAeFw0yMzA4MTQwOTE2MjRaFw0yNjA2MDMwOTE2MjRaMBkx
FzAVBgNVBAMMDmV4YW1wbGUtY2EuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA3IVnvJbtRqx+Rz4wadq2eRHuZlGrydSGg8RMtImTVrcqyd3WRR3i
PZrEo9H1KuUusut6TgTTyrSNyVREJqITrZ3v9l+OuFq9LnBmV5Ut9uZWorXFLO4I
S41BMTJ/2tbgjtqNkaBPpUrQOA0VkttRwLCMcIR/7G7ObxZNxBq+60mtukBpDF7z
p9lbIXoVunLo31mRanetefbM/YgQfRL0+EAtjfSc/guuomjS2yPtzFyvafXeXiP7
OtWdax844RnQyj/gdE4N8oI3IKADFDW5sUeNST54BrobV5QmfwHs1XC1ZTGGIBLu
0tF62MdEqAqL33DTfgrcPo/gchg1xAseBQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQBjU5UYmYWhmfKq+l23uz3o1JkigKshqTZPrNxLwiDjWAHFl6D8V2mWX3Xf2rT9
P08Gxw9pHvn0KmgnwNyQW5s1zrnKldsxuRC++sZAcW25iwRSKVT4Mvk8r9UP3sGr
e45jt+0OnQcijjFBGeQtkfmfGQqQ5hkGqUqgTs3yHHzi7RbueBjIZrQhcft+TJg9
BUErR1HogGuz/eu4yTGHIsb/CPFWFaKuxJIwjQsKvdoE2HKhDf7sOX8k5SL+KeoQ
JQwRtRWNZBFhUrzizV/bmKIB2ymBngfH1OB24JX4pPLt9og7FY92Lv+sLAzxfIHS
JA2SpFYQeLTJNM8nsL/q/dDU
-----END CERTIFICATE-----
"""

let leafCertificateForTLSIssuedFromCustomCARoot = """
-----BEGIN CERTIFICATE-----
MIICsjCCAZoCCQD3XtnOig4QMjANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5l
eGFtcGxlLWNhLmNvbTAeFw0yMzA4MTQwOTE3MDJaFw0yNDA4MTMwOTE3MDJaMB0x
GzAZBgNVBAMMEmV4YW1wbGUtc2VydmVyLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBANSngp1ea6XFCi/MsEFsamf3ujH3gDV0qWMi7dt2wIFLfpGX
CPIyOGn7NLCJIShw/TujvlOHLqwYGUxu+lIN/c5kU0B1PDurYEcUTR10zidOXAmi
rjFwgccERjYKbugvfxm/mU39lmOob5PkFC3p6V9qFpARwQaK/q2t0j/Sku5tBvaY
GPtyygi6W/I/+UwI8a7EorjAhk/IOwXUt5f6CcapGTltRZfG/qvpptwaMJTqwjW7
HFLBUj0e4j0uR7bduhOYlub16Uvn4QKHIcMIBnTBj3ClRQSECf3wdgtLbqBSGmEf
Xzb9tr02O+/TN3r0s77Y7INghVv7Tt3sNHVOTSECAwEAATANBgkqhkiG9w0BAQsF
AAOCAQEAnWeiYtVTKynyYOVy0ClN+L0fACM7JG45UCIlybaTpz+c4jnJ2AdacY0z
iFPJpnjl6NXzENvlZcu+unpWAM9WdeTv3pC5GdVasMfKMx2gMHyl9EAWlfD2z5zi
AshmWEInbzcrr6XqxfseIu7gI7cuWElxQ4fje4PUaCTz0yaGPhWwzuWpNuG6b1nw
8pjlKcg1uyUDZqthPNt3sGLJYMKgWfvRlfesPlHtU3pl0MEl3CuHyNuKNCt1DMXI
kdelPaIiQCZk+sYj5ZIr4yBogoZu06fm0R0FYrcYpB4844GHzLezBjnn1OfJ8DB4
UqR5CcyLWQfLe/HrAX7CZPh+UxYVWQ==
-----END CERTIFICATE-----
"""

let privateKeyForLeafCertificate = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUp4KdXmulxQov
zLBBbGpn97ox94A1dKljIu3bdsCBS36RlwjyMjhp+zSwiSEocP07o75Thy6sGBlM
bvpSDf3OZFNAdTw7q2BHFE0ddM4nTlwJoq4xcIHHBEY2Cm7oL38Zv5lN/ZZjqG+T
5BQt6elfahaQEcEGiv6trdI/0pLubQb2mBj7csoIulvyP/lMCPGuxKK4wIZPyDsF
1LeX+gnGqRk5bUWXxv6r6abcGjCU6sI1uxxSwVI9HuI9Lke23boTmJbm9elL5+EC
hyHDCAZ0wY9wpUUEhAn98HYLS26gUhphH182/ba9Njvv0zd69LO+2OyDYIVb+07d
7DR1Tk0hAgMBAAECggEBAJeUq8L2+e6YzFEUK5MG77YaXEufq3DvLoqu7DNiq4e+
Q4MN0N+rMpFA8ebgaJVGLQvlBRbPJlKffvD/rkjtFjyXQMyShJPX7fHco7daelSE
Q5DOuDIfizJMdquwtiulJ4k4DNQN7bQt7RLTIhs0QBi2K00YiqnaS/2LCHJb7EYs
fldMiJTe405d6gCBqI6tl1IVh56DbJiSEuWoqK2n0UuediN4ZHbDvi+QnRAfBww7
kc+QJvEZ6XhjLifK7TM9fc1yxgMGcjeAvemdjHsFtp7EbvXuRNTGx5kmUYUaI0qC
HAvANl8SlBpJLd6ezZIWm+NeHwckg+IrozoR5bEtVm0CgYEA8U3Z38nVJgSOffqA
Bx665Vha8hxzUVVlDg4cqV/oJzyeclF+9xRp3FHO65icfLYeav3DnATVirTRcZwq
gyL0akHGDj2c9Xi6LWXHCul1OIgzoz0XOrK2jj31d9NJ3rIgxXOdaVIz6narhbDT
cwwIF/SPlfhjUdMy1E9dbH+GQQcCgYEA4Zr7vjP91hjTDNB3GuAYhlBkH7DRkNLU
LU2rmmFXwXQu3YrWq/EDRG4+oh4AZ/WaTV7JoAFIkd1hy5ptYRTPHfI0zgo3Ma8S
HkjnOieXebAPWKIGkzdUqx1BssRtsTOiMKrIAt0HYE2X1fL/jAy+LopOlfTcRYhQ
gIgeNiFf/pcCgYAGyw9IKpFymYw9ZbD3All2nW8qA70HXCUVKTaLWiTZ/e3kAAFY
CV4VksQFg+1b4XCnyG8aVFSCrCZ9UU0tFe3Vk/Z0bi2eB4EOSCA7YWkoZ0U04kJm
J6PWC05+yhb5SwB7Lo8O6P6HKkIX6Gt7gKo1qm/kY/K/2fdDXNyfclOgPwKBgApO
fEW6NlR7mdiyBV7y8evg7FIOT+Sf3RWcwMQywkGSPznbx+bfAdk0eCQL3tThAYWb
WPa4WEphpMAac/jFbJjfoc3v5Ymdh+ReTEH54Q+sHWddL5O2KWYP1hqGosQ/qZ8z
jiOjWVzq7o7VpRsO0flqVCDBqPZ8PcFBdq/eYnZNAoGAQs9rvJD0fb9mPYm974z1
z/ynHRZoqB35VlOPs7DTd2wDHXB7PSfd/neadaqaHVQe9T3weZJJn24ugSFKqoGj
hK0YjA/Td2nrk9fpd2uKGnuEZiEfpkWgLOVBmepUHH2if8VIwSvaWU79U7LtbN4l
uSMcdpsHt7eQr1f+p7s2rZc=
-----END PRIVATE KEY-----
"""

let leafCertificateForClientAuthenticationIssuedFromCustomCARoot = """
-----BEGIN CERTIFICATE-----
MIICzDCCAbSgAwIBAgIJAPde2c6KDhAzMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNV
BAMMDmV4YW1wbGUtY2EuY29tMB4XDTIzMDgxNDA5MjAwM1oXDTI0MDgxMzA5MjAw
M1owGTEXMBUGA1UEAwwOZXhhbXBsZS1jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDbu1C/CXQwhTk5QDrjsPDFRkn3ta8WzbCGlab4IvTqLRkU
7tSJG5vSr7pfwMEpHPhTzJ46TK8Df9TZGkgO9ww/DTY7YPGDN1I4Lfj3fprzRx+C
UvsMI57nJJBNwIBeAr0dgX3L7z0BTxRdLckrdXvO99rX9AVUXTlzxEPrw4oafgRv
rljB0Uclh/bopuLsXGLiE4iN6jAM9z5f+ByOwCESJ8BngITuJIvE4hLEBXmZxAuR
8wxdRwQyjDPHszmhbuMQU8oCtmQdoNKcUTQKekM8+6M3jsBRVLm8nun/56wvmlxl
wpRBWoenGtlnR+kJ8ZfbWu4PyZ8QXB4o0OyshWWLAgMBAAGjFzAVMBMGA1UdJQQM
MAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAmEueGA6sOYuhmY6GIq17R
vWHVFo8valIbEd1BlLe4GDGgFm5NBRIqusnQzHV9g5CS9RQC+97eHciiPt2t875u
WKiZ5awNyQEHH7cfUY8Fj82xeNqaQ2EHtlNYNxRwcrxkZ6gFewby0a9zuT+kk9z4
+1fa96zKM2gv3JvwDW9UV2Wfg87NpUygrflwArrRmHYKMKfJyWItM1hROULCFs62
sJJAbeEdolImUpRkUm+0A9yYKihc2iybvDUATJrveSI5Fuam63sslDvEFmD3ZF3s
swIUwzhSHvX4LVa35ylN+fL4fkcfCdq29w8OMeL/T7JKbTgcZ6wERHf+BTfzmniH
-----END CERTIFICATE-----
"""

let privateKeyForClientAuthentication = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDbu1C/CXQwhTk5
QDrjsPDFRkn3ta8WzbCGlab4IvTqLRkU7tSJG5vSr7pfwMEpHPhTzJ46TK8Df9TZ
GkgO9ww/DTY7YPGDN1I4Lfj3fprzRx+CUvsMI57nJJBNwIBeAr0dgX3L7z0BTxRd
LckrdXvO99rX9AVUXTlzxEPrw4oafgRvrljB0Uclh/bopuLsXGLiE4iN6jAM9z5f
+ByOwCESJ8BngITuJIvE4hLEBXmZxAuR8wxdRwQyjDPHszmhbuMQU8oCtmQdoNKc
UTQKekM8+6M3jsBRVLm8nun/56wvmlxlwpRBWoenGtlnR+kJ8ZfbWu4PyZ8QXB4o
0OyshWWLAgMBAAECggEBAM1NIe+sdJwVDddZFOzC2ONpfhjs70/eFU5aKyxy9OSM
CIBPedM1MY1T1U47+f5g7ADYEQqltWwOlx/V93fMCewrev1V4bHZEYAeLB2KdFpT
nLQWtiusaH7M4etTrlyoMGyOHaxatmQvr/Yznl91oJ1LZXUasZQWmmR4/4EcLT/7
vJrobJaVYR2APCj8rVvHfbmkbWAedRlc6T931/tD/K38z67NfdL7NUrsVKHZGXtg
QSnx0C6ZmWWND4dpR2HPy7E18WgX2ocLYYtKlAeUjnur5DGZAniLanMbKZVPGE9I
pCol2mbrJwMTxPPSxTFaJhNfngGc1WhbJ44COhTWRYkCgYEA+F5aYvUc0hKhRUq8
r/xi6UarRlQUZq1YFIyb1ohfHiiW02rQQbYAbENezJ5CTxEo8+OIiX4Rt81RKr0I
4+hUFgGKMxOG59buXUfJaX3td4ViEXElcTQvMvY/SG1hwWEHQex2F/5j6WZkJl+v
Eh7p2x0JRvXf14m2V3VJ2Q58cTcCgYEA4nu1A6Vwffmju2yJYkQKrT0hcwAe2ks1
AvOPajAepXbcZvhxv9U/3HifNR1H3sWwDoU8WdtkX6sGvw6d8roGEhtm/gkjdYII
70nNV0KLRhHz5jp2yZlmJfvvTuRO7v2DGyGOp/J8WSK4zEZWt3hPF7KcJeGuyONa
d/oe3NYvaE0CgYBp4q/eKGmVFeQzSl2PGaaBlWNHpGjeLWCzwg5eM915WgyTLaKD
oTgk78PmsEHMu6Ad+g8nrtuW5K2J7vVvVIkkqJtmkxicloEgu44er1Uh83ePwBEa
ZgkJTPpFwnw+mUMi09C1AftOchyYT4qvywYgKAzgd8pqdYeLWbGWHBrpmQKBgQCs
j/EVvCH/+gtkrIfo1UsFQASSaM8ZKCBWBVmKYOuYyv2Xf0i8DzE/PLCheZPfCuTf
y2h2VpEdy2OyguKZpF8nwLUybagUymUgXS0VhWA0nU0mZ/lGFZkc694kUBRMR+By
9ZiKIlnYWHpROm6sEADDX5VVz6Sq739o1qxZOuCYKQKBgQDdpvNme2Tapq9xpzP1
57+kCmw8oINos+epiePxwCHGBi+fD7KHzd3ksbDuJjEHWvOmEiNZlMq2tm+b0z3S
sY9yNFGm8MReuagVbMrrXQMrKEMgjD16iaJEb/iTNkiuXP8svEplNCtCTx9CPvwF
yjs/D/6w2xhrlaheHU9naVLj4Q==
-----END PRIVATE KEY-----
"""

// This is a root certificate used to setup and test sending CA names to
// a client during client authentication.
// This certificate is used to test having multiple root certificates in a directory.
let secondaryRootCertificateForClientAuthentication = """
-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIUDxjYloPbo7PQteeQLKW499sRxm0wDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPU2FtcGxlUHJvamVjdENBMB4XDTIyMDgwOTE4NDQyMloX
DTIzMDgxMTE4NDQyMlowGjEYMBYGA1UEAwwPU2FtcGxlUHJvamVjdENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Q19OwSP4UJo35NZ0rg/+bAbBh+v
n7lilsPwLwhmhkwWZVSTPQr8bk5ceUGJtPups3w0d1oM/t7oC43O38sFwkCYL5nt
Z6YuQfP0ZijDjO6WiQr+gwyaAZt84/Rm1MHYqF1gBCDFQhcba3CTSd4HQzls+uRF
EaWqu4n706e10ed9Se1uAqeufYRdGPijskFNYmw+MgXWFC/WrY/TXRIoIQsj/g8A
jC66Ovriz+nXWYjPBSLdyXY69WVR5v6qksMeuJAYv37nsWL1H9436Q3WhxlLZ3Hl
v3SI13Kk6y7Sp5TYDeomeMi+9aAHOtvZfZcBEw5yLCkJSXGQL3nIpk7oDQIDAQAB
oyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICpDANBgkqhkiG9w0B
AQsFAAOCAQEAx+Ajc4SnzSS/1BpK+bVK2y0vH6NmF9Y9xjAi06pAWOtNpXBTH8Qe
QdQbB/00nUDccEcIoEn46WDKwW4ebGKa4sn2BAalM0W2UoPMX0UYtUDPyNkeK8Q+
MQVOaZX295g9t6sfQ/rbRQRGJHFH7VsRQPGHo/vYG91+ZS6judUUZw7Mcltaay2y
ljU3QeOeO3m553tfw/MwY6UWiSs9jyZumtzxL3WS/LCssxwnknkE5IM2CA8IzBfM
VShvzuAwd3a5ZTju3jD1cK0mwlbEYNw0xj+wjBLqwFuJI/CnQzGSElvQy0v2ygjr
R6S+ZRBlGxAnjKbTEMg53A+0XkGg/Kgexg==
-----END CERTIFICATE-----
"""

let samplePemCerts = "\(samplePemCert)\n\(samplePemCert)"
let sampleDerCert = pemToDer(samplePemCert)
let sampleDerKey = pemToDer(samplePemKey)
let sampleECDerKey = pemToDer(sampleECPemKey)
// No DER version of the private key becuase encrypted DERs aren't real.

func pemToDer(_ pem: String) -> Data {
    var lines = [String]()

    // This is very inefficient, but it doesn't really matter because this
    // code is run very infrequently and only in testing. Blame the inefficiency
    // on Linux Foundation, which currently lacks String.enumerateLines.
    let originalLines = pem.split(separator: "\n")
    for line in originalLines {
        let line = String(line)
        if !line.hasPrefix("-----") {
            lines.append(line)
        }
    }

    let encodedData = lines.joined(separator: "")
    return Data(base64Encoded: encodedData)!
}

// This function generates a random number suitable for use in an X509
// serial field. This needs to be a positive number less than 2^159
// (such that it will fit into 20 ASN.1 bytes).
// This also needs to be portable across operating systems, and the easiest
// way to do that is to use either getentropy() or read from urandom. Sadly
// we need to support old Linuxes which may not possess getentropy as a syscall
// (and definitely don't support it in glibc), so we need to read from urandom.
// In the future we should just use getentropy and be happy.
func randomSerialNumber() -> ASN1_INTEGER {
    let bytesToRead = 20
    let fd = open("/dev/urandom", O_RDONLY)
    precondition(fd != -1)
    defer {
        close(fd)
    }

    var readBytes = Array.init(repeating: UInt8(0), count: bytesToRead)
    let readCount = readBytes.withUnsafeMutableBytes {
        return read(fd, $0.baseAddress, bytesToRead)
    }
    precondition(readCount == bytesToRead)

    // Our 20-byte number needs to be converted into an integer. This is
    // too big for Swift's numbers, but BoringSSL can handle it fine.
    let bn = CNIOBoringSSL_BN_new()
    defer {
        CNIOBoringSSL_BN_free(bn)
    }
    
    _ = readBytes.withUnsafeBufferPointer {
        CNIOBoringSSL_BN_bin2bn($0.baseAddress, $0.count, bn)
    }

    // We want to bitshift this right by 1 bit to ensure it's smaller than
    // 2^159.
    CNIOBoringSSL_BN_rshift1(bn, bn)

    // Now we can turn this into our ASN1_INTEGER.
    var asn1int = ASN1_INTEGER()
    CNIOBoringSSL_BN_to_ASN1_INTEGER(bn, &asn1int)

    return asn1int
}

func generateRSAPrivateKey() -> OpaquePointer {
    let exponent = CNIOBoringSSL_BN_new()
    defer {
        CNIOBoringSSL_BN_free(exponent)
    }

    CNIOBoringSSL_BN_set_u64(exponent, 0x10001)

    let rsa = CNIOBoringSSL_RSA_new()!
    let generateRC = CNIOBoringSSL_RSA_generate_key_ex(rsa, CInt(2048), exponent, nil)
    precondition(generateRC == 1)

    let pkey = CNIOBoringSSL_EVP_PKEY_new()!
    let assignRC = CNIOBoringSSL_EVP_PKEY_assign_RSA(pkey, rsa)
    
    precondition(assignRC == 1)
    return pkey
}

func generateECPrivateKey(curveNID: CInt = NID_X9_62_prime256v1) -> OpaquePointer {
    let ctx = CNIOBoringSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil)!
    defer {
        CNIOBoringSSL_EVP_PKEY_CTX_free(ctx)
    }

    precondition(CNIOBoringSSL_EVP_PKEY_keygen_init(ctx) == 1)
    precondition(CNIOBoringSSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveNID) == 1)

    var pkey: OpaquePointer? = nil
    precondition(CNIOBoringSSL_EVP_PKEY_keygen(ctx, &pkey) == 1)

    return pkey!
}

func addExtension(x509: OpaquePointer, nid: CInt, value: String) {
    var extensionContext = X509V3_CTX()
    
    CNIOBoringSSL_X509V3_set_ctx(&extensionContext, x509, x509, nil, nil, 0)
    let ext = value.withCString { (pointer) in
        return CNIOBoringSSL_X509V3_EXT_nconf_nid(nil, &extensionContext, nid, UnsafeMutablePointer(mutating: pointer))
    }!
    CNIOBoringSSL_X509_add_ext(x509, ext, -1)
    CNIOBoringSSL_X509_EXTENSION_free(ext)
}

func generateSelfSignedCert(keygenFunction: () -> OpaquePointer = generateRSAPrivateKey) -> (NIOSSLCertificate, NIOSSLPrivateKey) {
    let pkey = keygenFunction()
    let x = CNIOBoringSSL_X509_new()!
    CNIOBoringSSL_X509_set_version(x, 2)

    // NB: X509_set_serialNumber uses an internal copy of the ASN1_INTEGER, so this is
    // safe, there will be no use-after-free.
    var serial = randomSerialNumber()
    CNIOBoringSSL_X509_set_serialNumber(x, &serial)
    
    let notBefore = CNIOBoringSSL_ASN1_TIME_new()!
    var now = time(nil)
    CNIOBoringSSL_ASN1_TIME_set(notBefore, now)
    CNIOBoringSSL_X509_set_notBefore(x, notBefore)
    CNIOBoringSSL_ASN1_TIME_free(notBefore)
    
    now += 60 * 60  // Give ourselves an hour
    let notAfter = CNIOBoringSSL_ASN1_TIME_new()!
    CNIOBoringSSL_ASN1_TIME_set(notAfter, now)
    CNIOBoringSSL_X509_set_notAfter(x, notAfter)
    CNIOBoringSSL_ASN1_TIME_free(notAfter)
    
    CNIOBoringSSL_X509_set_pubkey(x, pkey)
    
    let commonName = "localhost"
    let name = CNIOBoringSSL_X509_get_subject_name(x)
    commonName.withCString { (pointer: UnsafePointer<Int8>) -> Void in
        pointer.withMemoryRebound(to: UInt8.self, capacity: commonName.lengthOfBytes(using: .utf8)) { (pointer: UnsafePointer<UInt8>) -> Void in
            CNIOBoringSSL_X509_NAME_add_entry_by_NID(name,
                                                     NID_commonName,
                                                     MBSTRING_UTF8,
                                                     UnsafeMutablePointer(mutating: pointer),
                                                     ossl_ssize_t(commonName.lengthOfBytes(using: .utf8)),
                                                     -1,
                                                     0)
        }
    }
    CNIOBoringSSL_X509_set_issuer_name(x, name)
    
    addExtension(x509: x, nid: NID_basic_constraints, value: "critical,CA:FALSE")
    addExtension(x509: x, nid: NID_subject_key_identifier, value: "hash")
    addExtension(x509: x, nid: NID_subject_alt_name, value: "DNS:localhost")
    addExtension(x509: x, nid: NID_ext_key_usage, value: "critical,serverAuth,clientAuth")
    
    CNIOBoringSSL_X509_sign(x, pkey, CNIOBoringSSL_EVP_sha256())
    
    return (NIOSSLCertificate.fromUnsafePointer(takingOwnership: x), NIOSSLPrivateKey.fromUnsafePointer(takingOwnership: pkey))
}

final class BackToBackEmbeddedChannel {
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private(set) var loop: EmbeddedEventLoop


    init() {
        self.loop = EmbeddedEventLoop()
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)
    }

    func run() {
        self.loop.run()
    }

    func connectInMemory() throws {
        let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
        let connectFuture = self.client.connect(to: addr)
        self.server.pipeline.fireChannelActive()
        try self.interactInMemory()
        try connectFuture.wait()
    }

    func interactInMemory() throws {
        var workToDo = true

        while workToDo {
            workToDo = false

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: IOData.self)
            let serverDatum = try self.server.readOutbound(as: IOData.self)

            // Reads may trigger errors. The write case is automatic.
            try self.client.throwIfErrorCaught()
            try self.server.throwIfErrorCaught()

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
                workToDo = true
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
                workToDo = true
            }
        }
    }
}
