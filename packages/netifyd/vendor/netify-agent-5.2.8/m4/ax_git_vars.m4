dnl Nexwall stub for the vendor's private AX_GIT_VARS macro. This project
dnl pins PKG_VERSION explicitly in the OpenWrt package rather than deriving
dnl it from "git describe", so real values are not needed here.
dnl GIT_RELEASE is used directly in src/nd-util.cpp (the agent's own version
dnl banner, "Netify Agent/<value>"); a real build there would want an actual
dnl commit-derived string, this vendored copy uses the pinned version instead.
AC_DEFUN([AX_GIT_VARS], [
    AC_SUBST([GIT_LAST_COMMIT_HASH], [unknown])
    AC_SUBST([GIT_LAST_COMMIT_DATE], [unknown])
    AC_DEFINE_UNQUOTED([GIT_RELEASE], ["${PACKAGE_VERSION}-nexwall"], [Release identifier shown in the agent's version banner.])
])
