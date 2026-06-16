#
# Custom compilation modes
#   Compile one target several times with different
#   configuration variables.
#
# Sample:
#    CFLAGS = -O2
#    bin_PROGRAM = prog
#    prog_SOURCES = prog.c
#
#    AM_MODES = debug
#    CFLAGS_debug = -O0 -g
#
# Result:
#   prog       - compiled with -O2
#   prog-debug - compiled with -O0 -g
#

AM_MODES ?=

# Variables that can be overrided with $(var)_$(mode)
AM_MODE_OVERRIDE += CC CXX CFLAGS CPPFLAGS DEFS LDFLAGS LIBS

## add "-MODE" string before file extension
# 1-mode, 2-filename
ModeName = $(basename $(2))-$(1)$(suffix $(2))

## add mode suffix to all plain filenames
# 1-mode, 2-file names, options
ModeFilter = $(foreach f,$(2),$(if $(filter /% -%,$(f)),$(f),$(call ModeName,$(1),$(f))))

## set per-target var
# 1-dbgvar, 2-var, 3-final
ModeVarX = $(3): $(2) = $$($(1))$(NewLine)

# 1-mode, 2-var, 3-final
ModeVarOverride = $(if $($(2)_$(1)),$(call ModeVarX,$(2)_$(1),$(2),$(3)))

# 1-mode, 2-final
ModeVarOverrideAll = $(foreach v,$(AM_MODE_OVERRIDE),$(call ModeVarOverride,$(1),$(v),$(2)))

## copy target, replace vars
# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags,6=mode,7-newtgt,8-cleantgt,9-list
define AddModes4
$(trace8)

$(IFEQ) ($$(filter $(9),$$(am_TARGETLISTS)),)
am_TARGETLISTS += $(9)
$(ENDIF)

# add new target to old list
$(9) += $(7)

# copy details, change library names
$(8)_SOURCES := $$($(1)_SOURCES)
nodist_$$(8)_SOURCES := $$(nodist_$(1)_SOURCES)
$(8)_CPPFLAGS := $$($(1)_CPPFLAGS)
$(8)_CFLAGS := $$($(1)_CFLAGS)
$(8)_LDFLAGS := $$($(1)_LDFLAGS)
$(8)_LIBADD := $$(call ModeFilter,$(6),$$($(1)_LIBADD))
$(8)_LDADD := $$(call ModeFilter,$(6),$$($(1)_LDADD))

# add variable replacements
$(call ModeVarOverrideAll,$(6),$(call FinalTargetFile,$(8),$(7),$(3)))

endef

## add clean name, list name
# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags,6-mode,7-raw tgt
AddModes3 = $(call AddModes4,$(1),$(2),$(3),$(4),$(5),$(6),$(7),$(call CleanName,$(7)),$(subst $(Space),_,$(5)_$(4)_$(3)))

## loop over modes
# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
AddModes2 = $(trace5)$(foreach m,$(AM_MODES),$(call AddModes3,$(1),$(2),$(3),$(4),$(5),$(m),$(call ModeName,$(m),$(2))))

## ignore small primaries
# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
AddModes = $(trace5)$(if $(filter $(3),$(AM_BIG_PRIMARIES)),$(call AddModes2,$(1),$(2),$(3),$(4),$(5)))

# Install hook
AM_TARGET_HOOKS += AddModes
