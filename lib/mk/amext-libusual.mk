#
# Merge libusual sources with target sources
#
# Usage:
#   USUAL_DIR = <libusual source tree>
#
#   <target>_EMBED_LIBUSUAL = 1
#
# It adds module sources into <target>_SOURCES
# and -I$(USUAL_DIR) to _CPPFLAGS.
#

##
## Utility functions for libusual link
##

_USUAL_DIR = $(call JoinPath,$(srcdir),$(USUAL_DIR))
_USUAL_DIR2 = $(call JoinPath,$(_USUAL_DIR),usual)

# module names from sources (plus headers)
UsualMods = $(trace1)$(shell $(_USUAL_DIR)/find_modules.sh $(_USUAL_DIR) $(sort $(wildcard $(addprefix $(srcdir)/,$(1)))))

# full-path sources based on module list
UsualSrcsFull = $(trace1)$(sort $(wildcard $(addprefix $(_USUAL_DIR2)/,$(addsuffix *.[ch],$(1)))))

# remove USUAL_DIR
UsualStrip = $(trace1)$(subst $(_USUAL_DIR)/,,$(1))

# simple-path sources based on module list
UsualSrcs = $(call UsualStrip,$(call UsualSrcsFull,$(1)))

# usual sources from user source file list
UsualSources = $(if $(1),$(call UsualSrcsFull,$(call UsualMods,$(1))))

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define EmbedLibUsual
$(trace5)

# embed libusual objects directly
$(IFEQ) ($$($(1)_EMBED_LIBUSUAL),1)

$(1)_SOURCES := $$($(1)_SOURCES) $$(call UsualSources, $$($(1)_SOURCES))
EXTRA_$(1)_SOURCES := $$(EXTRA_$(1)_SOURCES) \
	$$(call UsualSources, \
		$$(EXTRA_$(1)_SOURCES) \
		$$(nodist_$(1)_SOURCES) \
		$$(nodist_EXTRA_$(1)_SOURCES))

$(1)_CPPFLAGS += -I$$(USUAL_DIR)

$(ENDIF)

endef

AM_TARGET_HOOKS += EmbedLibUsual

EXTRA_DIST += $(_USUAL_DIR)/find_modules.sh $(_USUAL_DIR)/usual/config.h.in
