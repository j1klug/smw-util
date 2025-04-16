DESCRIPTION = "Uses the imx-secure-enclave library to create an AES 256 key"
HOMEPAGE = "http://www.multitech.net/"
PRIORITY = "optional"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

PR = "r0"
DEPENDS = "imx-secure-enclave"

SRC_URI = " \
		file://aeskeygen.c \
		file://aesencrypt.c \
		file://aesdecrypt.c \
         "

S = "${WORKDIR}"
DEBUGFLAG=""
# DEBUGFLAG="-g"

do_compile() {
	${CC} ${DEBUGFLAG} -D PSA_COMPLIANT -I ${STAGING_INCDIR}/hsm -v ${CFLAGS} ${LDFLAGS} -o aeskeygen aeskeygen.c -lele_hsm
	${CC} ${DEBUGFLAG} -D PSA_COMPLIANT -I ${STAGING_INCDIR}/hsm -v ${CFLAGS} ${LDFLAGS} -o aesencrypt aesencrypt.c -lele_hsm
	${CC} ${DEBUGFLAG} -D PSA_COMPLIANT -I ${STAGING_INCDIR}/hsm -v ${CFLAGS} ${LDFLAGS} -o aesdecrypt aesdecrypt.c -lele_hsm
}

do_install() {
	install -d  ${D}${bindir}/
	install -m 0755 aeskeygen ${D}${bindir}/
	install -m 0755 aesencrypt ${D}${bindir}/
	install -m 0755 aesdecrypt ${D}${bindir}/
}
