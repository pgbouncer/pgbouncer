#
# Support for C++ language
#
# - extensions: .cc, .cpp, cxx
# - CXX, CXXFLAGS
# - AM_CXXFLAGS, <tgt>_CXXFLAGS
#

# autoconfigurable values
ifneq ($(filter-out @%,@CXX@),)
CXX = @CXX@
CXXFLAGS = @CXXFLAGS@
endif
CXX ?= c++
CXXFLAGS ?= -O -g

# fixme: add warning flags to CXXFLAGS
CXXFLAGS += $(WFLAGS)

# helper variables
CXXLD ?= $(CXX)
CXXCOMPILE ?= $(CXX) $(AM_DEFS) $(DEFS) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS)
CXXLINK ?= $(CXXLD) $(AM_CXXFLAGS) $(CXXFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

# full compile command
define AM_LANG_CXX_COMPILE
	$(E) "CXX" $<
	$(Q) $(LTCOMPILE) $(CXXCOMPILE) $(OBJDEPS) -c -o $@ $<
endef

# full link command
define AM_LANG_CXX_LINK
	$(E) "CXXLD" $@
	$(Q) $(LTLINK) $(CXXLINK) $^ $(AM_LIBS) $(LIBS) $(AM_LT_RPATH)
endef

# source file extensions for c++
AM_LANG_CXX_SRCEXTS = .cc .cpp cxx

# register per-target variable
AM_TARGET_VARIABLES += CXXFLAGS

# register new language
AM_LANGUAGES += CXX
