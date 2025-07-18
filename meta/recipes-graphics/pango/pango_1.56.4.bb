SUMMARY = "Framework for layout and rendering of internationalized text"
DESCRIPTION = "Pango is a library for laying out and rendering of text, \
with an emphasis on internationalization. Pango can be used anywhere \
that text layout is needed, though most of the work on Pango so far has \
been done in the context of the GTK+ widget toolkit. Pango forms the \
core of text and font handling for GTK+-2.x."
HOMEPAGE = "http://www.pango.org/"
BUGTRACKER = "http://bugzilla.gnome.org"
SECTION = "libs"
LICENSE = "LGPL-2.0-or-later"

LIC_FILES_CHKSUM = "file://COPYING;md5=3bf50002aefd002f49e7bb854063f7e7"

inherit gnomebase gi-docgen upstream-version-is-even gobject-introspection

UPSTREAM_CHECK_REGEX = "pango-(?P<pver>\d+\.(?!9\d+)\d+\.\d+)"

GIR_MESON_ENABLE_FLAG = "enabled"
GIR_MESON_DISABLE_FLAG = "disabled"

SRC_URI[archive.sha256sum] = "17065e2fcc5f5a5bdbffc884c956bfc7c451a96e8c4fb2f8ad837c6413cb5a01"

DEPENDS = "glib-2.0 glib-2.0-native fontconfig freetype virtual/libiconv cairo harfbuzz fribidi"
DEPENDS += "${@' python3-docutils-native' if d.getVar('GIDOCGEN_ENABLED') == 'True' else ''}"

PACKAGECONFIG ??= "${@bb.utils.filter('DISTRO_FEATURES', 'x11', d)}"

PACKAGECONFIG[x11] = ",,virtual/libx11 libxft"
PACKAGECONFIG[thai] = "-Dlibthai=enabled,-Dlibthai=disabled,libthai"

GIR_MESON_OPTION = 'introspection'
GIDOCGEN_MESON_OPTION = 'documentation'

LEAD_SONAME = "libpango-1.0*"

FILES:${PN} = "${bindir}/* ${libdir}/libpango*${SOLIBS}"

RPROVIDES:${PN} += "pango-modules pango-module-indic-lang \
                    pango-module-basic-fc pango-module-arabic-lang"

BBCLASSEXTEND = "native nativesdk"
