SUMMARY = "Machine-readable files for the SPIR-V Registry"
SECTION = "graphics"
HOMEPAGE = "https://www.khronos.org/registry/spir-v"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=d14ee3b13f42e9c9674acc5925c3d741"

SRCREV = "aa6cef192b8e693916eb713e7a9ccadf06062ceb"
SRC_URI = "git://github.com/KhronosGroup/SPIRV-Headers;protocol=https;branch=main"
PE = "1"
# These recipes need to be updated in lockstep with each other:
# glslang, vulkan-headers, vulkan-loader, vulkan-tools, spirv-headers, spirv-tools
# vulkan-validation-layers, vulkan-utility-libraries, vulkan-volk.
# The tags versions should always be sdk-x.y.z, as this is what
# upstream considers a release.
UPSTREAM_CHECK_GITTAGREGEX = "sdk-(?P<pver>\d+(\.\d+)+)"

inherit cmake

BBCLASSEXTEND = "native nativesdk"
