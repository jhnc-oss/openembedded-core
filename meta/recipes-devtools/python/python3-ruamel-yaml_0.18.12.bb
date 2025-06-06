SUMMARY = "YAML parser/emitter that supports roundtrip preservation of comments, seq/map flow style, and map key order."
HOMEPAGE = "https://pypi.org/project/ruamel.yaml/"

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=5cc5d45e8a30c81dade6ca1928caa515"

PYPI_PACKAGE = "ruamel.yaml"
UPSTREAM_CHECK_PYPI_PACKAGE = "${PYPI_PACKAGE}"

inherit pypi python_setuptools_build_meta

SRC_URI[sha256sum] = "5a38fd5ce39d223bebb9e3a6779e86b9427a03fb0bf9f270060f8b149cffe5e2"

RDEPENDS:${PN} += "\
    python3-shell \
    python3-datetime \
    python3-netclient \
"

BBCLASSEXTEND = "native nativesdk"
