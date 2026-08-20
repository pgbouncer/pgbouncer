AM_FEATURES = msvc

# make it work also when included from test/Makefile
top_srcdir = $(dir $(filter %build.mk, $(MAKEFILE_LIST)))
top_builddir = $(top_srcdir)
abs_top_srcdir := $(abspath $(top_srcdir))
abs_top_builddir := $(abs_top_srcdir)

include $(abs_top_srcdir)/mk/antimake.mk
