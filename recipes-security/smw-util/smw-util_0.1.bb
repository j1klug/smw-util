DESCRIPTION = "Uses the smw library to compare a hash"
HOMEPAGE = "http://www.multitech.net/"
PRIORITY = "optional"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

PR = "r0"
DEPENDS = "smw"

SRC_URI = " \
	    file://elesha512.c \
	    file://simplehash.c \
	    file://hsmhash.c \
         "
S = "${WORKDIR}"

do_compile() {
	${CC} -g -I ${STAGING_INCDIR}/smw -v ${CFLAGS} ${LDFLAGS} -o elesha512 elesha512.c -lsmw -lteec -lele_hsm
	${CC} -g -I ${STAGING_INCDIR}/smw -v ${CFLAGS} ${LDFLAGS} -o simplehash simplehash.c -lsmw -lteec -lele_hsm
	${CC} -g -I ${STAGING_INCDIR}/hsm -v ${CFLAGS} ${LDFLAGS} -o hsmhash hsmhash.c -lteec -lele_hsm
}

do_install() {
	install -d ${D}${bindir}
	install -m 0755 elesha512 ${D}${bindir}/
	install -m 0755 simplehash ${D}${bindir}/
	install -m 0755 hsmhash ${D}${bindir}/
}
