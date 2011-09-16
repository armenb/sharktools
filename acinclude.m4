dnl Create an AC_UNDEFINE() function
AC_DEFUN([AC_UNDEFINE],
         [cp confdefs.h confdefs.h.tmp
          grep -v $1 < confdefs.h.tmp > confdefs.h
          rm confdefs.h.tmp
          ])
