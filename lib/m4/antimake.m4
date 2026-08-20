dnl
dnl  AMK_INIT: Generate initial makefile
dnl

AC_DEFUN([AMK_INIT], [

# if building separately from srcdir, write top-level makefile
if test "$srcdir" != "."; then
  echo "include $srcdir/Makefile" > Makefile
fi

])
