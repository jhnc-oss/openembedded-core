SUMMARY = "Download, build, install, upgrade, and uninstall Python packages"
HOMEPAGE = "https://pypi.org/project/setuptools"
SECTION = "devel/python"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=141643e11c48898150daa83802dbc65f"

inherit pypi python_setuptools_build_meta

CVE_PRODUCT = "python3-setuptools python:setuptools"

SRC_URI += " \
            file://0001-_distutils-sysconfig.py-make-it-possible-to-substite.patch"

SRC_URI[sha256sum] = "f36b47402ecde768dbfafc46e8e4207b4360c654f1f3bb84475f0a28628fb19c"

DEPENDS += "python3"

RDEPENDS:${PN} = "\
    python3-compile \
    python3-compression \
    python3-ctypes \
    python3-email \
    python3-html \
    python3-json \
    python3-netserver \
    python3-numbers \
    python3-pickle \
    python3-pkg-resources \
    python3-pkgutil \
    python3-plistlib \
    python3-shell \
    python3-stringold \
    python3-threading \
    python3-unittest \
    python3-unixadmin \
    python3-xml \
"

BBCLASSEXTEND = "native nativesdk"

# The pkg-resources module can be used by itself, without the package downloader
# and easy_install. Ship it in a separate package so that it can be used by
# minimal distributions.
PACKAGES =+ "python3-pkg-resources "
FILES:python3-pkg-resources = "${PYTHON_SITEPACKAGES_DIR}/pkg_resources/*"
RDEPENDS:python3-pkg-resources = "\
    python3-compression \
    python3-email \
    python3-plistlib \
    python3-pprint \
"

# This used to use the bootstrap install which didn't compile. Until we bump the
# tmpdir version we can't compile the native otherwise the sysroot unpack fails
INSTALL_WHEEL_COMPILE_BYTECODE:class-native = "--no-compile-bytecode"
