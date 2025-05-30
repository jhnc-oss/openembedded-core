SUMMARY = "BSD replacement for libreadline"
DESCRIPTION = "Command line editor library providing generic line editing, \
history, and tokenization functions"
HOMEPAGE = "http://www.thrysoee.dk/editline/"
SECTION = "libs"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://COPYING;md5=1e4228d0c5a9093b01aeaaeae6641533"

DEPENDS = "ncurses"

inherit autotools

SRC_URI = "http://www.thrysoee.dk/editline/${BP}.tar.gz \
           file://stdc-predef.patch \
          "
SRC_URI[sha256sum] = "23792701694550a53720630cd1cd6167101b5773adddcb4104f7345b73a568ac"

# configure hardcodes /usr/bin search path bypassing HOSTTOOLS
CACHED_CONFIGUREVARS += "ac_cv_path_NROFF=/bin/false"

# remove at next version upgrade or when output changes
PR = "r1"
HASHEQUIV_HASH_VERSION .= ".1"

BBCLASSEXTEND = "native nativesdk"
