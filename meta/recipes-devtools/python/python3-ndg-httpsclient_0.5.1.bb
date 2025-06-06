SUMMARY = "Provides enhanced HTTPS support for httplib and urllib2 using PyOpenSSL"
HOMEPAGE = "https://github.com/cedadev/ndg_httpsclient/"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://MANIFEST.in;md5=ce22c0cd986d2de3f7073cd6b5523ae0"

SRC_URI[sha256sum] = "d72faed0376ab039736c2ba12e30695e2788c4aa569c9c3e3d72131de2592210"

inherit pypi setuptools3 update-alternatives

PYPI_PACKAGE = "ndg_httpsclient"
UPSTREAM_CHECK_PYPI_PACKAGE = "${PYPI_PACKAGE}"

DEPENDS += " \
    python3-pyopenssl \
    python3-pyasn1 \
"

RDEPENDS:${PN} += " \
    python3-datetime \
    python3-logging \
    python3-pyopenssl \
    python3-pyasn1 \
"

BBCLASSEXTEND = "native nativesdk"

ALTERNATIVE:${PN} = "ndg_httpclient"
ALTERNATIVE_LINK_NAME[ndg_httpclient] = "${bindir}/ndg_httpclient"
ALTERNATIVE_PRIORITY = "30"
