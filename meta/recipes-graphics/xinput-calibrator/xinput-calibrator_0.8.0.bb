SUMMARY = "Touchscreen calibration program for X11"
HOMEPAGE = "http://www.freedesktop.org/wiki/Software/xinput_calibrator"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://src/calibrator.cpp;endline=22;md5=1bcba08f67cdb56f34021557898e4b5a"
DEPENDS = "virtual/libx11 libxi libxrandr"

inherit autotools pkgconfig features_check
REQUIRED_DISTRO_FEATURES = "x11"

SRCREV = "970b574b8f7b0d6f2613d343191f47814f2dfaa4"

SRC_URI = "git://gitlab.freedesktop.org/xorg/app/xinput-calibrator;protocol=https;branch=master;tag=v${PV} \
           file://30xinput_calibrate.sh \
           file://Allow-xinput_calibrator_pointercal.sh-to-be-run-as-n.patch \
           "

EXTRA_OECONF += "--with-gui=x11"

do_install:append() {
    install -d ${D}${bindir}
    install -m 0755 ${S}/scripts/xinput_calibrator_pointercal.sh ${D}${bindir}/xinput_calibrator_once.sh

    install -d ${D}${sysconfdir}/X11/Xsession.d/
    install -m 0755 ${UNPACKDIR}/30xinput_calibrate.sh ${D}${sysconfdir}/X11/Xsession.d/

    install -d ${D}${sysconfdir}/xdg/autostart
    sed -e 's,^Exec=.*,Exec=${bindir}/xinput_calibrator_once.sh,' ${S}/scripts/xinput_calibrator.desktop > ${D}${sysconfdir}/xdg/autostart/xinput_calibrator.desktop
}

FILES:${PN} += "${sysconfdir}/xdg/autostart"
RDEPENDS:${PN} = "xinput formfactor"
RRECOMMENDS:${PN} = "pointercal-xinput"
