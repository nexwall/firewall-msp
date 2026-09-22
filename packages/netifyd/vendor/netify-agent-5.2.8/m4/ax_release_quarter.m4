dnl Nexwall stub for the vendor's private AX_RELEASE_QUARTER macro (same
dnl reasoning as ax_git_vars.m4 and ax_check_progs.m4: this project pins
dnl PKG_VERSION explicitly, it does not use the vendor's own quarterly
dnl release-numbering scheme).
AC_DEFUN([AX_RELEASE_QUARTER], [
    AC_SUBST([ND_RELEASE_QUARTER], [1])
])
