dnl Nexwall stub for the vendor's private AX_GIT_VARS macro. This project
dnl pins PKG_VERSION explicitly in the OpenWrt package rather than deriving
dnl it from "git describe", so real values are not needed here.
AC_DEFUN([AX_GIT_VARS], [
    AC_SUBST([GIT_LAST_COMMIT_HASH], [unknown])
    AC_SUBST([GIT_LAST_COMMIT_DATE], [unknown])
])
