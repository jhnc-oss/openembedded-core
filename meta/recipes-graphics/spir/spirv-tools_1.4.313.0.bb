SUMMARY  = "The SPIR-V Tools project provides an API and commands for \
processing SPIR-V modules"
DESCRIPTION = "The project includes an assembler, binary module parser, \
disassembler, validator, and optimizer for SPIR-V."
HOMEPAGE = "https://github.com/KhronosGroup/SPIRV-Tools"
SECTION = "graphics"
LICENSE  = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3b83ef96387f14655fc854ddc3c6bd57"

SRCREV = "a62abcb402009b9ca5975e6167c09f237f630e0e"
SRC_URI = "git://github.com/KhronosGroup/SPIRV-Tools.git;branch=main;protocol=https \
           "
PE = "1"
# These recipes need to be updated in lockstep with each other:
# glslang, vulkan-headers, vulkan-loader, vulkan-tools, spirv-headers, spirv-tools
# vulkan-validation-layers, vulkan-utility-libraries, vulkan-volk.
# The tags versions should always be sdk-x.y.z, as this is what
# upstream considers a release.
UPSTREAM_CHECK_GITTAGREGEX = "sdk-(?P<pver>\d+(\.\d+)+)"

inherit cmake

DEPENDS = "spirv-headers"

EXTRA_OECMAKE += "\
    -DSPIRV-Headers_SOURCE_DIR=${STAGING_EXECPREFIXDIR} \
    -DSPIRV_TOOLS_BUILD_STATIC=OFF \
    -DBUILD_SHARED_LIBS=ON \
    -DSPIRV_SKIP_TESTS=ON \
"

# Force the version description "git describe" related non-reproducibility
do_compile:prepend() {
    export FORCED_BUILD_VERSION_DESCRIPTION="${PV}"
}

do_install:append:class-target() {
    # Properly set _IMPORT_PREFIX in INTERFACE_LINK_LIBRARIES so that dependent
    # tools can find the right library
    sed -i ${D}${libdir}/cmake/SPIRV-Tools/SPIRV-ToolsTarget.cmake \
        -e 's:INTERFACE_LINK_LIBRARIES.*$:INTERFACE_LINK_LIBRARIES "\$\{_IMPORT_PREFIX\}/${baselib}":'
}

# all the libraries are unversioned, so don't pack it on PN-dev
SOLIBS = ".so"
FILES_SOLIBSDEV = ""

PACKAGES =+ "${PN}-lesspipe"
FILES:${PN}-lesspipe = "${base_bindir}/spirv-lesspipe.sh"
RDEPENDS:${PN}-lesspipe += "${PN} bash"

BBCLASSEXTEND = "native nativesdk"
