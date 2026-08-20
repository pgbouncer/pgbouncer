#! /usr/bin/make -f

#
# antimake.mk - automake syntax with GNU Make
#
# Copyright (c) 2011  Marko Kreen
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Goals:
# - Clean user Makefiles, by using automake syntax
# - Clean output during build
# - Optional ties with `autoconf` and `libtool`
# - Automatic dependency tracking
# - Avoid separate build step for Makefiles
# - No extra tools needed except GNU Make

# Usage without autoconf:
# - copy antimake.mk into source dir, then: include antimake.mk
# - copy/link antimake.mk into PATH, then:  include $(shell antimake.mk)
#
# Usage with autoconf:
# - Copy to antimake.mk.in at top dir, then process with autoconf
#   to antimake.mk and include that one in Makefiles.
#
# - Have config.mak.in that also includes antimake.mk.
#   Suggestion: the separate file should include antimake.mk
#   using $(abs_top_srcdir) to support separate build dir.
#
# - Include config and antimake.mk separately in user Makefiles

##
## Startup hacks
##

# detect GNU make version, confuse others
$(eval GNUMAKE380=1)
GNUMAKE381=$(or ,$(GNUMAKE380))
define GNUMAKE382 =
$(GNUMAKE381)
endef

# give error of too old
ifeq ($(GNUMAKE381),)
$(error GNU Make 3.81+ required)
endif


# extra targets if this file is executed directly
ifeq ($(words $(MAKEFILE_LIST)), 1)

.PHONY: show-location show-config

# default: print location. For "include $(shell antimake.mk)"-style usage.
show-location:
	@echo $(MAKEFILE_LIST)

# show autoconfigurable variables
show-config:
	@grep '@[^ ]*@$$' $(MAKEFILE_LIST)

endif


##
## Allow this file to be processed through autoconf
##

#
# to extract autoconfigurable values:
#    $ grep '@[^ ]*@$' antimake.mk > config.mk.in
#    $ antimake.mk show-config > config.mk.in
#
ifneq ($(filter-out @%,@PACKAGE_NAME@),)

PACKAGE_NAME = @PACKAGE_NAME@
PACKAGE_TARNAME = @PACKAGE_TARNAME@
PACKAGE_VERSION = @PACKAGE_VERSION@
PACKAGE_STRING = @PACKAGE_STRING@
PACKAGE_URL = @PACKAGE_URL@
PACKAGE_BUGREPORT = @PACKAGE_BUGREPORT@

PORTNAME = @PORTNAME@
EXEEXT = @EXEEXT@
HAVE_CC_DEPFLAG = @HAVE_CC_DEPFLAG@

# C language
CC = @CC@
CPP = @CPP@
CPPFLAGS = @CPPFLAGS@
CFLAGS = @CFLAGS@
DEFS = @DEFS@
WFLAGS = @WFLAGS@

# linking
LD = @LD@
LDFLAGS = @LDFLAGS@
LIBS = @LIBS@

# static and shared libs
AR = @AR@
ARFLAGS = @ARFLAGS@
RANLIB = @RANLIB@
LIBTOOL = @LIBTOOL@

# other tools
SHELL = @SHELL@
INSTALL = @INSTALL@
INSTALL_PROGRAM = @INSTALL_PROGRAM@
INSTALL_SCRIPT = @INSTALL_SCRIPT@
INSTALL_DATA = @INSTALL_DATA@
MKDIR_P = @MKDIR_P@
SED = @SED@
AWK = @AWK@
GREP = @GREP@
EGREP = @EGREP@
STRIP = @STRIP@

# install locations
prefix = @prefix@
exec_prefix = @exec_prefix@
bindir = @bindir@
includedir = @includedir@
sbindir = @sbindir@
libexecdir = @libexecdir@
datarootdir = @datarootdir@
datadir = @datadir@
sysconfdir = @sysconfdir@
docdir = @docdir@
mandir = @mandir@
libdir = @libdir@
localedir = @localedir@
pkgdatadir = @pkgdatadir@
pkgconfigdir = @pkgconfigdir@
aclocaldir = @aclocaldir@

# autoconf values for top dir
abs_top_srcdir ?= @abs_top_srcdir@
abs_top_builddir ?= @abs_top_builddir@
nosub_top_srcdir ?= @top_srcdir@
nosub_top_builddir ?= @top_builddir@

endif # end of @xx@ values

##
## In case of missing autoconf values, provide sane defaults
##

PACKAGE_NAME ?= package
PACKAGE_TARNAME ?= $(PACKAGE_NAME)
PACKAGE_VERSION ?= 0.0
PACKAGE_STRING ?= $(PACKAGE_NAME) $(PACKAGE_VERSION)
PACKAGE_URL ?=
PACKAGE_BUGREPORT ?=

PORTNAME ?= unix
EXEEXT ?=
HAVE_CC_DEPFLAG ?= yes

# C language
CC ?= cc
CPP ?= cpp
CPPFLAGS ?=
CFLAGS ?= -O -g
DEFS ?=

# warning flags are keps separately to allow easy override
WFLAGS ?= -Wall
# add them to main flags now
CFLAGS += $(WFLAGS)

# linking
LD ?= ld
LDFLAGS ?=
LIBS ?=

# static and shared libs
LIBTOOL ?= libtool
AR ?= ar
ARFLAGS ?= rcs
ifeq ($(ARFLAGS),rv)
ARFLAGS = rcs
endif
RANLIB ?= ranlib

# other tools
SHELL ?= /bin/sh
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_SCRIPT ?= $(INSTALL)
INSTALL_DATA ?= $(INSTALL)
MKDIR_P ?= mkdir -p
SED ?= sed
AWK ?= awk
GREP ?= grep
EGREP ?= grep -E
STRIP ?= strip

# install locations
prefix ?= /usr/local
exec_prefix ?= ${prefix}
bindir ?= ${exec_prefix}/bin
includedir ?= ${prefix}/include
sbindir ?= ${exec_prefix}/sbin
libexecdir ?= ${exec_prefix}/libexec
datarootdir ?= ${prefix}/share
datadir ?= ${datarootdir}
sysconfdir ?= ${prefix}/etc
docdir ?= ${datarootdir}/doc/${PACKAGE_TARNAME}
mandir ?= ${datarootdir}/man
libdir ?= ${exec_prefix}/lib
localedir ?= ${datarootdir}/locale
pkgdatadir ?= ${datarootdir}/${PACKAGE_TARNAME}
pkgconfigdir ?= ${libdir}/pkgconfig
aclocaldir ?= ${datarootdir}/aclocal

# autoconf values for top dir
abs_top_srcdir ?= $(CURDIR)
abs_top_builddir ?= $(CURDIR)

# make sure nosub vals are not empty
ifeq ($(nosub_top_builddir),)
nosub_top_builddir = .
endif
ifeq ($(nosub_top_srcdir),)
nosub_top_srcdir = .
endif

##
## Variables for user makefiles
##

# current subdirectory location from top dir (foo/bar)
SUBLOC ?= .

# subdirectories in current directory
SUBDIRS ?=

# extra files for clean targets
CLEANFILES ?=
DISTCLEANFILES ?=
MAINTAINERCLEANFILES ?=

# Additional flags for Makefile use, to avoid need
# to touch flags coming from autoconf/cmdline
AM_DEFS ?=
AM_CPPFLAGS ?=
AM_CFLAGS ?=
AM_LDFLAGS ?=
AM_LIBTOOLFLAGS ?=

AM_MAKEFLAGS ?=
AM_LIBS ?=

# libusual sources, for embedded usage
USUAL_DIR ?= .

# V=1 -> verbose build
V ?= 0

# turn on function tracing
AM_TRACE ?=

# default formats for 'dist'
AM_DIST_DEFAULT ?= gzip

##
## Non-user-serviceable area
##

# Hacking:
#
# - Uppercase names are simple (late) variables, lowercase names - targets,
#   mixedcase - functions that need to be $(call)-ed.
#
# - Minimal amount of shell should be used here.
#
# - Minimal amount of := and $(eval)
#
# - It's useful to indent the expressions for easier understanding.
#   Later the indendation needs to be removed, as whitespace is significant for Make.
#   Several functions must not add any extra whitespace.
#
# GNU Make features in new versions:
#
#   3.80 - 2002-10-03: base version.  $(eval) $(value) $(MAKEFILE_LIST) $(.VARIABLES) $(call fixes)
#   3.81 - 2006-04-01: $(or), $(and), $(lastword), $(abspath), $(realpath), $(info), $(flavor)
#   3.82 - 2010-07-28: private, undefine, define var :=
#
# This file should use only features from 3.80

##
## command helpers
##

CCLD ?= $(CC)
COMPILE ?= $(CC) $(AM_DEFS) $(DEFS) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LINK ?= $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

AM_AR ?= $(AR) $(ARFLAGS)

LIBTOOLCMD ?= $(LIBTOOL) $(LIBTOOLQ) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS)

RM = rm -f


##
## Internals
##

# varables that can be set per-target with target_VAR
# they appear as AM_foo.  [Not supported: COMPILE]
AM_TARGET_VARIABLES += CFLAGS CPPFLAGS LDFLAGS LIBTOOLFLAGS DEFS LIBS

# list of language (rather compiler) names
AM_LANGUAGES += C

AM_BIG_PRIMARIES += LIBRARIES LTLIBRARIES PROGRAMS
AM_SMALL_PRIMARIES += HEADERS SCRIPTS DATA MANS

# list of destinations per primary
AM_DESTINATIONS += bin lib libexec sbin \
		   data doc include locale man sysconf \
		   pkgdata pkgconfig aclocal \
		   noinst EXTRA

# primaries where 'dist' is default
AM_DIST_PRIMARIES += HEADERS

AM_PRIMARIES = $(AM_BIG_PRIMARIES) $(AM_SMALL_PRIMARIES)

# distclean does rm -rf on that
OBJDIR = .objs

# extension for objects
OBJEXT = .o

# extension for static libraries
LIBEXT = .a

# files that need to be converted to objects
AM_SRCEXTS = $(foreach lang,$(AM_LANGUAGES),$(AM_LANG_$(lang)_SRCEXTS))

# target types - big/small: with/without objects
# list of flags, 'noinst' is taken as dest, 'base' is always default
AM_FLAGS = base nobase dist nodist

## configure non-defult target params
AM_PROGRAMS_InstFunc = ProgInstall
AM_LTLIBRARIES_InstFunc = LTLibInstall
AM_LTLIBRARIES_OBJEXT = .lo
AM_SCRIPTS_InstFunc = ScriptInstall
AM_MANS_InstFunc = ManInstall

# files to distribute
am_DISTFILES :=
am_FINAL_DISTFILES = $(sort $(am_DISTFILES))
AM_DIST_BASE = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)

AM_ALL_TARGETS =

##
## Make dependencies work
##

HAVE_CC_DEPFLAG ?= yes
ifeq ($(HAVE_CC_DEPFLAG),yes)
OBJDEPS = -MD -MP -MT $@ -MF $@.d
endif


##
## Quiet by default, 'make V=1' shows commands
##

# 1-dir
MkDir = $(MKDIR_P) $(1)

# 1-fmt, 2-args
Printf = printf $(1) $(2)

CTX ?=
ifeq ($(V), 0)
E = @$(call Printf,"%-4s %-8s %s\n","$(CTX)")
Q = @
LIBTOOLQ = --silent
MAKEFLAGS += --no-print-directory
else
E = @true
Q =
LIBTOOLQ = --silent
endif


##
## libtool activation
##

# libtool activates when detects %.lo / %.la pattern
LTCOMPILE = $(if $(filter %.lo,$@),$(LIBTOOLCMD) --mode=compile)
LTLINK = $(if $(filter %.la %.lo,$^),$(LIBTOOLCMD) --mode=link)
LTCLEAN = $(LIBTOOLCMD) --mode=clean


##
## Default setup for C
##

AM_LANG_C_SRCEXTS = .c
define AM_LANG_C_COMPILE
	$(E) "CC" $<
	$(Q) $(LTCOMPILE) $(COMPILE) $(OBJDEPS) -c -o $@ $<
endef
define AM_LANG_C_LINK
	$(E) "CCLD" $@
	$(Q) $(LTLINK) $(LINK) $^ $(AM_LIBS) $(LIBS) $(AM_LT_RPATH)
endef

##
## Various other shortcuts
##

define ar_lib
	$(E) "AR" $@
	$(Q) $(AM_AR) $@ $^
	$(E) "RANLIB" $@
	$(Q) $(RANLIB) $@
endef

# 1 - dir
define ProgInstall
	$(E) "INSTALL" "$< $(1)"
	$(Q) $(call MkDir,$(1))
	$(Q) $(INSTALL_PROGRAM) $< $(1)
endef

# 1 - dir
define ScriptInstall
	$(E) "INSTALL" "$< $(1)"
	$(Q) $(call MkDir,$(1))
	$(Q) $(INSTALL_SCRIPT) $< $(1)
endef

# 1 - dir
define DataInstall
	$(E) "INSTALL" "$< $(1)"
	$(Q) $(call MkDir,$(1))
	$(Q) $(INSTALL_DATA) $< $(1)
endef

# 1 - dir, add manX subdir
ManInstall = $(call DataInstall,$(1)/man$(call LastWord,$(subst ., ,$<)))

# 1 - dir
define LTLibInstall
	$(E) "INSTALL" "$< $(1)"
	$(Q) $(call MkDir,$(1))
	$(Q) $(LIBTOOLCMD) --mode=install $(INSTALL) $< $(1)
endef


##
## Create .srcext -> .obj mapping for a language
##

# 1-tgt, 2-name, 3-srcext
define LangObjTarget
$(trace3)
$$(OBJDIR)/$(1)/%$(OBJEXT): %$(3)
	@$$(call MkDir,$$(dir $$@))
	$$(AM_LANG_$(2)_COMPILE)
$$(OBJDIR)/$(1)/%.lo: %$(3)
	@$$(call MkDir,$$(dir $$@))
	$$(AM_LANG_$(2)_COMPILE)
endef

# 1=tgt, 2=name
define LangSetup
$(trace2)
$(foreach ext,$(AM_LANG_$(2)_SRCEXTS),$(call LangObjTarget,$(1),$(2),$(ext))$(NewLine))
endef


##
## Utility functions
##

# for function debugging, put them at the start of body
ifdef AM_TRACE
trace1=$(warning $0('$1'))
trace2=$(warning $0('$1','$2'))
trace3=$(warning $0('$1','$2','$3'))
trace4=$(warning $0('$1','$2','$3','$4'))
trace5=$(warning $0('$1','$2','$3','$4','$5'))
trace6=$(warning $0('$1','$2','$3','$4','$5','$6'))
trace7=$(warning $0('$1','$2','$3','$4','$5','$6','$7'))
trace8=$(warning $0('$1','$2','$3','$4','$5','$6','$7','$8'))
trace9=$(warning $0('$1','$2','$3','$4','$5','$6','$7','$8','$9'))
endif

# for use inside $(eval)
IFDEF = ifdef
IFEQ = ifeq
IFNEQ = ifneq
ELSE = else
ENDIF = endif

# returns 'true' if $1==$2
Eq = $(if $(1)$(2),$(if $(findstring $(1),$(2)),$(if $(findstring $(2),$(1)),true)),true)

Not = $(if $(1),,true)
Neq = $(call Not,$(call Eq,$(1),$(2)))

# replace [-./] with '_'
CleanName = $(subst /,_,$(subst -,_,$(subst .,_,$(1))))

# return last word from word list
LastWord = $(if $(1),$(word $(words $(1)),$(1)))

Empty =
Space = $(Empty) $(Empty)
# twice to unconfuse syntax hiliters
SQuote = '
SQuote = '
define NewLine


endef

# quote str for shell
ShellQuote = '$(subst $(SQuote),'\$(SQuote)',$(1))'

# replace extensions
# 1-src ext list
# 2-target ext
# 3-source list
ReplaceExts = $(foreach ext,$(1),$(patsubst %$(ext),%$(2),$(filter %$(ext),$(3))))

# objs with objdir from source list (1-cleantgt, 2-src list)
SourceObjs = $(trace1)$(call SourceObjsExt,$(1),$(OBJEXT),$(2))

# objs with objdir from source list
# 1-cleantgt, 2-objext, 3-srcs list
SourceObjsExt = $(addprefix $(call JoinPath,$(OBJDIR),$(1))/, $(call ReplaceExts,$(AM_SRCEXTS),$(2),$(3)))

# dependency files from object files, must match OBJDEPS
DepFiles = $(sort $(wildcard $(addsuffix .d,$(1))))

# per-target var override, 1=target, 2=varname
# if foo_VAR exists, expand to:
#   build_foo install_foo clean_foo: AM_VAR = $(foo_VAR)


# 1-tgt, 2-var, 3-final
TgtVar2 = $(3): AM_$(2) = $$($(1)_$(2))$(NewLine)
TgtVar = $(if $($(1)_$(2)),$(call TgtVar2,$(1),$(2),$(3)))

# loop TgtVar over AM_TARGET_VARIABLES, 1=target, 2-final
VarOverride = $(foreach var,$(AM_TARGET_VARIABLES),$(call TgtVar,$(1),$(var),$(2)))

# check if actual target (.h, .exe) is nodist based on primary and flags
# 1-prim 2-flags
TargetNoDist = $(strip $(if $(filter nodist,$(2)), \
                            true, \
			    $(if $(filter dist,$(2)), \
			         , \
			         $(filter-out $(AM_DIST_PRIMARIES),$(1)))))

# return sources that match language
# 1-lang
# 2-sources
LangFiles = $(filter $(addprefix %,$(AM_LANG_$(1)_SRCEXTS)),$(2))

# return list of langs that match sources.
# 1-sources
LangList = $(strip $(foreach lang,$(AM_LANGUAGES),$(if $(call LangFiles,$(lang),$(1)),$(lang))))

# 1-sources
LinkLangList = $(foreach lang,$(call LangList,$(1)),$(if $(AM_LANG_$(lang)_LINK),$(lang)))

# pick linker variable based on sources, fallback to C
# 1-sources
DetectLinkVar = AM_LANG_$(call LastWord,C $(call LinkLangList,$(1)))_LINK

# convert 'foo/bar' -> '../..'
UpDirStep1 = $(subst /, ,$(1))
UpDirStep2 = $(foreach dir,$(call UpDirStep1,$(1)),../)
UpDirStep3 = $(subst / ,/,$(call UpDirStep2,$(1)))
UpDirStep4 = $(patsubst %/,%,$(call UpDirStep3,$(1)))
UpDir = $(if $(filter-out .,$(1)),$(call UpDirStep4,$(1)),.)

#
# AntiMake requires that joining clean names must result in clean names.
#
# Thus:
#   JoinPath(.,foo) -> foo
#   JoinPath(foo,/abs) -> /abs
#   JoinPath(a/b,../c) -> a/c
#   JoinPath(a,../../b/c) -> ../b/c
#

# 1-path, 2-last name :  foo => . | /foo => / | foo/bar => foo
CutLastName = $(if $(filter $(2),$(1)),.,$(if $(filter /$(2),$(1)),/,$(patsubst %/$(2),%,$(1))))

# 1-path component, remove last elem :
CutLast = $(call CutLastName,$(1),$(lastword $(subst /, ,$(1))))

# 1/2 : actual place where / is put
JoinPathFinal = $(if $(filter /,$(1)),$(1)$(2),$(1)/$(2))

# 1/2 : second starts with ../, remove it and last component of $(1)
JoinPath5 = $(call JoinPath,$(call CutLast,$(1)),$(patsubst ../%,%,$(2)))

# 1/2: check if first ends with ..
JoinPath4 = $(if $(filter .. %/..,$(1)),$(call JoinPathFinal,$(1),$(2)),$(call JoinPath5,$(1),$(2)))

# 1/2 : check if second starts with ..; otherwise join
JoinPath3 = $(if $(filter ../%,$(2)),$(call JoinPath4,$(1),$(2)),$(call JoinPathFinal,$(1),$(2)))

# 1/2 : skips component if '.'
JoinPath2 = $(if $(filter-out .,$(1)),$(if $(filter-out .,$(2)),$(call JoinPath3,$(1),$(2)),$(1)),$(2))

# 1/2 : check if b is absolute, otherwise fix minor problems
JoinPath = $(trace2)$(if $(filter /%,$(2)),$(2),$(call JoinPath2,$(if $(filter /,$(1)),$(1),$(patsubst %/,%,$(1))),$(patsubst ./%,%,$(2))))

##
## Parse target list variables
##

## pick out components from name, call function
# 1-varname, 2-words, 3-func, 4-func arg
# func args: 1-var, 2-prim, 3-dest, 4-flags, 5-arg
ParseName = $(call $(3),$(1),$(filter $(AM_PRIMARIES),$(2)),$(filter $(AM_DESTINATIONS),$(2)),$(filter $(AM_FLAGS),$(2)),$(4))

ForEachList = $(foreach var,$(2),$(call ParseName,$(var),$(subst _, ,$(var)),$(1),$(3)))

## try reconstruct name, if fails, its a random variable
# 1-var, 2-prim,3-dest,4-flags
CheckName = $(if $(call Eq,$(subst _, ,$(1)),$(strip $(4) $(call LastWord,$(3)) $(call LastWord,$(2)))),$(1))

## also check if variable is filled
# 1-var, 2-prim,3-dest,4-flags
CheckNameFull = $(if $(call CheckName,$(1),$(2),$(3),$(4)),$(if $($(1)),$(1)))

##
## Loop over targets in list variables
##

## call function on parsed target
# 1-var, 2-prim, 3-dest, 4-flags, 5-func
# func args: 1-cleantgt, 2-tgt, 3-prim, 4-dest, 5-flags
ForEachTarget2 = $(foreach tgt,$($(1)),$(call $(5),$(call CleanName,$(tgt)),$(tgt),$(2),$(3),$(4)))

## ForEachTarget: call function on all targets in lists
# 1-func, 2- var list
# func args: 1-cleantgt, 2-tgt, 3-prim, 4-dest, 5-flags
ForEachTarget = $(call ForEachList,ForEachTarget2,$(2),$(1))


## EMBED_SUBDIRS relocations

## add subdir to files
# 1-subdir, 2-file list
RelocFiles = $(foreach f,$(2),$(if $(filter -%,$(f)),$(f),$(call JoinPath,$(1),$(f))))


# 1-dir, 2-pfx, 3-full
RelocOneFlag2 = $(2)$(call JoinPath,$(1),$(patsubst $(2)%,%,$(3)))

# 1-dir, 2-flag
RelocOneFlag = $(if $(filter -L%,$(2)), \
                    $(call RelocOneFlag2,$(1),-L,$(2)), \
		    $(if $(filter -I%,$(2)), \
                         $(call RelocOneFlag2,$(1),-I,$(2)), \
			 $(2)))

## Relocate relative files, relative -I/-L, ignore -*
# 1-dir, 2- flaglist
RelocFlags = $(strip $(if $(filter-out .,$(1)), \
                          $(foreach flg,$(2),$(call RelocOneFlag,$(1),$(flg))), \
		          $(2)))


## Separate build dir relocation

## non-local source dir: -Isrc/include -> -Isrc/include -I$(srcdir)/src/include
# 1-srcdir, 2-flag list
FixIncludes = $(strip $(if $(filter-out .,$(1)), \
			   $(foreach flg,$(2),$(call FixIncludes2,$(1),$(flg))), \
			   $(2)))
# 1-dir, 2-flg
FixIncludes2 = $(if $(filter -I%,$(2)), \
		    $(call FixIncludes3,$(1),$(patsubst -I%,%,$(2))), \
		    $(2))
# 1-dir, 2-orig dir
FixIncludes3 = -I$(2) -I$(call JoinPath,$(srcdir),$(2))


##
## Makefile fragments
##

### fill values
# abs_top_srcdir, abs_top_builddir
# nosub_top_builddir, nosub_top_srcdir
# 1 - subdir
define SetDirs
abs_builddir := $$(call JoinPath,$$(abs_top_builddir),$(1))
abs_srcdir := $$(call JoinPath,$$(abs_top_srcdir),$(1))
top_builddir := $$(call UpDir,$(1))
top_srcdir := $$(call JoinPath,$$(top_builddir),$$(nosub_top_srcdir))
builddir := .
$(IFEQ) ($$(nosub_top_srcdir),$$(nosub_top_builddir))
srcdir := .
$(ELSE)
srcdir := $$(call JoinPath,$$(top_srcdir),$(1))
$(ENDIF)
endef


##
## Embedded subdirs
##

# func args: 1-cleantgt, 2-tgt, 3-prim, 4-dest, 5-flags
define RelocBigTarget
$(trace5)
# move vars:
$(foreach var,$(AM_TARGET_VARIABLES),$(NewLine)$$(am_PFX)_$(1)_$(var) := $$($(1)_$(var)))

# move and relocate
EXTRA_$$(am_PFX)_$(1)_SOURCES := $$(call RelocFiles,$$(am_DIR),$$(EXTRA_$(1)_SOURCES))
$$(am_PFX)_$(1)_SOURCES := $$(call RelocFiles,$$(am_DIR),$$($(1)_SOURCES))
$$(am_PFX)_$(1)_DEPENDENCIES := $$(call RelocFiles,$$(am_DIR),$$($(1)_DEPENDENCIES))
$$(am_PFX)_$(1)_LDADD := $$(call RelocFiles,$$(am_DIR),$$($(1)_LDADD))
$$(am_PFX)_$(1)_LIBADD := $$(call RelocFiles,$$(am_DIR),$$($(1)_LIBADD))
$$(am_PFX)_$(1)_CFLAGS := $$(call RelocFlags,$$(am_DIR),$$($(1)_CFLAGS))
$$(am_PFX)_$(1)_CPPFLAGS := $$(call RelocFlags,$$(am_DIR),$$($(1)_CPPFLAGS))
$$(am_PFX)_$(1)_LDFLAGS := $$(call RelocFlags,$$(am_DIR),$$($(1)_LDFLAGS))

# clean vars
$(1)_SOURCES =
$(1)_LDADD =
$(1)_LIBADD =
$(foreach var,$(AM_TARGET_VARIABLES),$(NewLine)$(1)_$(var) = )
endef


## pick actual func
# func args: 1-cleantgt, 2-tgt, 3-prim, 4-dest, 5-flags
define RelocTarget
$(trace5)
$(if $(filter $(AM_BIG_PRIMARIES),$(3)),$(call RelocBigTarget,$(1),$(2),$(3),$(4),$(5)))
endef


## relocate target list
# func args: 1-var, 2-prim, 3-dest, 4-flags, 5-arg
define RelocTList
$(trace5)

# detect top and subdir target conflict - it's easier to detect
# and error out than to work around the rare case
$(IFNEQ) (,$$(filter $(2),$$(AM_BIG_PRIMARIES)))
$(IFEQ) (.,$$(am_DIR))
am_TOP_NAMES += $$(foreach tgt,$$($(1)),$$(call CleanName,$$(tgt)))
$(ELSE)
$(IFNEQ) (,$$(filter $$(am_TOP_NAMES),$$(foreach tgt,$$($(1)),$$(call CleanName,$$(tgt)))))
$$(error $$(NewLine)$$(NewLine)\
*** Target names used in top Makefile cannot be re-used in embedded Makefiles. $$(NewLine)\
*** The target variables (eg. <tgt>_SOURCES) conflict is not handled yet)
$(ENDIF)
$(ENDIF)
$(ENDIF)

# move value under real_%
$(IFEQ) ($(real_$(1)),)
real_$(1) :=
$(ENDIF)
real_$(1) += $$(call RelocFiles,$$(am_DIR),$$($(1)))
$(1) =

# remember in proper list
$(IFEQ) ($(3),EXTRA)
am_EXTRA_TARGETLISTS += real_$(1)
$(ELSE)
am_TARGETLISTS += real_$(1)
$(ENDIF)
endef


## process included values
# 1-dir, 2-pfx, 3-tlist
define EmbedProcess
$(trace3)

$(IFNEQ) ($$(filter $(1),$$(am_EMBED_DONE)),)
$$(error Double entry in EMBED_SUBDIRS: $(1))
$(ENDIF)

# init local vars
am_DIR := $(1)
am_LOC := $$(call JoinPath,$$(SUBLOC),$(1))
am_PFX := $(2)
am_EMBED_DONE += $(1)

# reloc & save vars
am_DISTFILES += $$(call RelocFiles,$$(am_DIR),$$(EXTRA_DIST))
am_CLEANFILES += $$(call RelocFiles,$$(am_DIR),$$(CLEANFILES))
am_DISTCLEANFILES += $$(call RelocFiles,$$(am_DIR),$$(DISTCLEANFILES))
am_MAINTAINERCLEANFILES += $$(call RelocFiles,$$(am_DIR),$$(MAINTAINERCLEANFILES))
am_EMBED_TODO += $$(call RelocFiles,$$(am_DIR),$$(EMBED_SUBDIRS))
am_SUBDIRS += $$(call RelocFiles,$$(am_DIR),$$(SUBDIRS))
am_DIST_SUBDIRS += $$(call RelocFiles,$$(am_DIR),$$(DIST_SUBDIRS))
# clean vars for new dir
EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
EMBED_SUBDIRS =
SUBDIRS =
DIST_SUBDIRS =

$(call SetDirs,$(call JoinPath,$(SUBLOC),$(1)))
$(call ForEachTarget,RelocTarget,$(3))
$(call ForEachList,RelocTList,$(3))
endef


## read Makefile.am, process it
# 1 - dir
DoEmbed = $(trace1)$(strip \
	$(if $(wildcard $(am_srcdir)/$(1)/Makefile.am), \
               $(eval include $(am_srcdir)/$(1)/Makefile.am $(NewLine)) \
	       $(eval $(call EmbedProcess,$(1),$(call CleanName,$(1)),$(AM_NONEXTRA_TLISTS) $(AM_EXTRA_TLISTS))), \
	     $(error $(SUBLOC)/Makefile failure: $(call JoinPath,$(SUBLOC),$(1)/Makefile.am) not found.)))

##
##  Fragments that build targets
##

# Note that variable initialization order is important here
# as some of them will be used immediately.

##
## Install target object
##

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define InstallTarget
$(trace5)

$(1)_DEST := $$(if $$($(4)dir),$$($(4)dir),$$(error '$(4)dir' empty))$(if $(filter nobase,$(5)),/$(dir $(2)))

$(1)_InstFunc := $$(if $$(AM_$(3)_InstFunc),$$(AM_$(3)_InstFunc),DataInstall)

# actual installation
.PHONY: install_$(1)
install: install_$(1)
install_$(1): $(2)
	$$(call $$($(1)_InstFunc),$$(DESTDIR)$$($(1)_DEST))

# hack to pass -rpath to LTLIBRARIES on build time (1)
$(2): AM_DEST = $$($(1)_DEST)

# simple uninstall - just remove files
.PHONY: uninstall_$(1)
uninstall: uninstall_$(1)
uninstall_$(1):
	$$(RM) $$(DESTDIR)$$($(1)_DEST)/$$(notdir $(2))

endef

# hack to pass -rpath to LTLIBRARIES on build time (2)
%.la: AM_LT_RPATH = $(if $(AM_DEST),-rpath $(AM_DEST))


##
## Rules for big target
##

# 1-varname, 2-ifset, 3-ifnotset
IfSet = $(if $(filter-out undefined,$(flavor $(1))),$(2),$(3))

# 1-clean, 2-raw, 3-prim
PROGRAMS_Final = $(if $($(1)_EXT),$(2)$($(1)_EXT),$(2)$(EXEEXT))
# 1-clean, 2-raw, 3-prim
LIBRARIES_Final = $(if $($(1)_EXT),$(2)$($(1)_EXT),$(patsubst %.a,%$(LIBEXT),$(2)))

# calculate target file name
# 1-clean, 2-raw, 3-prim
FinalTargetFile = $(call IfSet,$(3)_Final,$(call $(3)_Final,$(1),$(2),$(3)),$(2)$($(1)_EXT))

# 1-objs
FixObjs = $(patsubst %.a,%$(LIBEXT),$(1))

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define BigTargetBuild
$(trace5)
AM_ALL_TARGETS += $(1)

$(1)_ALLSRCS := $$($(1)_SOURCES) $$(EXTRA_$(1)_SOURCES) $$(nodist_$(1)_SOURCES) $$(nodist_EXTRA_$(1)_SOURCES)

# calculate OBJS from SOURCES
$(1)_OBJEXT := $$(if $$(AM_$(3)_OBJEXT),$$(AM_$(3)_OBJEXT),$$(OBJEXT))
$(1)_OBJS := $$(call SourceObjsExt,$(1),$$($(1)_OBJEXT), \
	                           $$($(1)_SOURCES) $$(nodist_$(1)_SOURCES))
$(1)_OBJS_CLEAN := $$($(1)_OBJS)

# include additional objects, move flags to _LIBS
$(IFEQ) ($(3),PROGRAMS)
$(1)_OBJS += $$(filter-out -%,$$($(1)_LDADD))
$(1)_LIBS += $$(filter -%,$$($(1)_LDADD))
$(ELSE)
$(1)_OBJS += $$(filter-out -%,$$($(1)_LIBADD))
$(1)_LIBS += $$(filter -%,$$($(1)_LIBADD))
$(ENDIF)

# autodetect linker, unless given
$(IFEQ) ($($(1)_LINK),)
$(1)_LINKVAR := $$(call DetectLinkVar,$$($(1)_ALLSRCS))
$(ELSE)
$(1)_LINKVAR := $(1)_LINK
$(ENDIF)

# calculate target file name
$(1)_FINAL = $(call FinalTargetFile,$(1),$(2),$(3))

# hook libtool into LTLIBRARIES cleanup
$(IFEQ) ($(3),LTLIBRARIES)
$(1)_RM = $$(LTCLEAN) $$(RM)
$(ELSE)
$(1)_RM = $$(RM)
$(ENDIF)

# fix includes in case of separate build dir
$(1)_CPPFLAGS := $$(call FixIncludes,$$(srcdir),$$($(1)_CPPFLAGS))
$(1)_CFLAGS := $$(call FixIncludes,$$(srcdir),$$($(1)_CFLAGS))

# load dependencies
-include .dummy. $$(call DepFiles, $$($(1)_OBJS))

# actual build, clean & install targets
.PHONY: build_$(1) clean_$(1)

# allow target-specific variables
$$(eval $$(call VarOverride,$(1),$(call FinalTargetFile,$(1),$(2),$(3))))

# build and clean by default, unless flagged EXTRA
$(IFNEQ) ($(4),EXTRA)
all: build_$(1)
$(ENDIF)
clean: clean_$(1)

# _DEPENDENCIES and nodist_SOURCES must exist before build starts.
$$(call FixObjs,$$($(1)_OBJS)): $$($(1)_DEPENDENCIES) $$(nodist_$(1)_SOURCES)

build_$(1): $$($(1)_FINAL)
$$($(1)_FINAL): $$(call FixObjs,$$($(1)_OBJS))
	@$$(call MkDir,$$(dir $$@))
	$$($(if $(filter LIBRARIES,$(3)),ar_lib,$$($(1)_LINKVAR)))

clean_$(1):
	$$(E) "CLEAN" "$$($(1)_FINAL)"
	$$(Q) $$($(1)_RM) -- $$($(1)_OBJS_CLEAN) $(if $(call TargetNoDist,$(3),$(5)),$$($(1)_FINAL))

DISTCLEANFILES += $$(nodist_$(1)_SOURCES) $$(nodist_EXTRA_$(1)_SOURCES)

$(foreach lang,$(AM_LANGUAGES),$(call LangSetup,$(1),$(lang)))

endef

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define BigTargetDist
am_DISTFILES += $$(filter-out $$(nodist_EXTRA_$(1)_SOURCES) $$(nodist_$(1)_SOURCES),$$($(1)_SOURCES) \
	     $$(EXTRA_$(1)_SOURCES)) $(if $(call TargetNoDist,$(3),$(5)),,$$($(1)_FINAL))
endef

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define MakeBigTarget
$(trace5)

# build if first time
$(IFEQ) ($(filter $(1),$(AM_ALL_TARGETS)),)
$(call BigTargetBuild,$(1),$(2),$(3),$(4),$(5))
$(call BigTargetDist,$(1),$(2),$(3),$(4),$(5))
$(ELSE)
# allow only EXTRA be double
$(IFNEQ) ($(4),EXTRA)
$$(error Target '$2' described listed several times)
$(ENDIF)
$(ENDIF)

# call InstallTarget, for dest != (EXTRA, noinst)
$(IFEQ) ($(filter EXTRA noinst,$(4)),)
$(call InstallTarget,$(1),$$($(1)_FINAL),$(3),$(4),$(5))
$(ENDIF)

endef


##
## Rules for small target
##

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define MakeSmallTarget
$(trace5)
AM_ALL_TARGETS += $(1)

# should the target file be distributed or cleaned?
$(IFEQ) ($(call TargetNoDist,$(3),$(5)),)
am_DISTFILES += $(2)
$(ELSE)
CLEANFILES += $(2)
$(ENDIF)

# build if not EXTRA
$(IFNEQ) ($(4),EXTRA)
all: $(2)
# install if not EXTRA or noinst
$(IFNEQ) ($(4),noinst)
$(call InstallTarget,$(1),$(2),$(3),$(4),$(5))
$(ENDIF)
$(ENDIF)

endef


##
## Fill GNU-style vars for subdir
##

# preferred to top_srcdir/top_builddir
topdir = $(top_builddir)

ifneq ($(nosub_top_builddir),.)
$(error Non-local builddir not supported)
endif

# initial locaton vars
$(eval $(call SetDirs,$(SUBLOC)))

ifneq ($(nosub_top_srcdir),$(nosub_top_builddir))
# use VPATH to find non-local sources
VPATH += $(srcdir)
# fix includes
AM_CPPFLAGS := $(call FixIncludes,$(srcdir),$(AM_CPPFLAGS))
AM_CFLAGS := $(call FixIncludes,$(srcdir),$(AM_CFLAGS))
endif


##
## O=<tgtdir>
##    if given, create wrapper makefiles in target dir
##    that include makefiles from source dir, then run
##    make from target dir.
##

ifneq ($(O),)

# 1-makefile
define WrapMakeFileCmd
	@$(call MkDir,$(dir $(O)/$(1)))
	@$(call Printf,'%s\n%s\n%s\n%s\n%s\n', \
		'abs_top_srcdir = $(CURDIR)' \
		'abs_top_builddir = $(call JoinPath,$(CURDIR),$(O))' \
		'nosub_top_srcdir = $(call UpDir,$(O))' \
		'nosub_top_builddir = .' \
		'include $(abs_top_srcdir)/$(1)') \
		> $(O)/$(1)
endef

# 1-makefile
WrapMakeFile = $(if $(wildcard $(O)/$(1)),,$(call WrapMakeFileCmd,$(1))$(NewLine))

# redirect whatever rule was given
.PHONY: all $(MAKECMDGOALS)
all $(filter-out all,$(MAKECMDGOALS)):
	$(if $(wildcard $(O)),,$(error O=$(O): Directory '$(O)' does not exist))
	$(foreach mk,$(filter-out /%,$(MAKEFILE_LIST)),$(call WrapMakeFile,$(mk)))
	$(Q) $(MAKE) O= -C $(O) $(MAKECMDGOALS)

# O=empty, this is main makefile
else

##
## main targets, tie them with subdir and local targets
##

# disable random rules
.SUFFIXES:

all: sub-all all-local
clean: sub-clean clean-local
install: sub-install install-local
uninstall: sub-uninstall uninstall-local
distclean: sub-distclean distclean-local
maintainer-clean: sub-maintainer-clean maintainer-clean-local
.PHONY: all clean install dist distclean maintainer-clean

# -local are empty targets by default
.PHONY: all-local clean-local install-local uninstall-local distclean-local maintainer-clean-local
all-local clean-local install-local uninstall-local distclean-local maintainer-clean-local:

##
## Actual embedding starts
##

AM_ALL_TLISTS2 = $(filter $(addprefix %,$(AM_PRIMARIES)),$(.VARIABLES))
AM_ALL_TLISTS = $(call ForEachList,CheckName,$(AM_ALL_TLISTS2))
AM_NONEXTRA_TLISTS = $(filter-out EXTRA_%,$(AM_ALL_TLISTS))
AM_EXTRA_TLISTS = $(filter EXTRA_%,$(AM_ALL_TLISTS))

am_srcdir := $(srcdir)
am_DIR := .
am_PFX :=
am_TARGETLISTS :=
am_EXTRA_TARGETLISTS :=
am_TOP_NAMES :=

# move top-level targets away
$(eval $(call ForEachList,RelocTList,$(AM_NONEXTRA_TLISTS)))
$(eval $(call ForEachList,RelocTList,$(AM_EXTRA_TLISTS)))

am_SUBDIRS := $(SUBDIRS)
am_DIST_SUBDIRS := $(DIST_SUBDIRS)
am_DISTFILES := $(EXTRA_DIST)
am_CLEANFILES := $(CLEANFILES)
am_DISTCLEANFILES := $(DISTCLEANFILES)
am_MAINTAINERCLEANFILES := $(MAINTAINERCLEANFILES)
am_EMBED_NOW := $(EMBED_SUBDIRS)
am_EMBED_DONE :=
am_EMBED_TODO :=
EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
SUBDIRS =
DIST_SUBDIRS =
EMBED_SUBDIRS =

$(foreach dir,$(am_EMBED_NOW),$(call DoEmbed,$(dir)))
am_EMBED_NOW := $(am_EMBED_TODO)
am_EMBED_TODO :=

$(foreach dir,$(am_EMBED_NOW),$(call DoEmbed,$(dir)))
am_EMBED_NOW := $(am_EMBED_TODO)
am_EMBED_TODO :=

$(foreach dir,$(am_EMBED_NOW),$(call DoEmbed,$(dir)))
am_EMBED_NOW := $(am_EMBED_TODO)
am_EMBED_TODO :=
$(if $(am_EMBED_NOW),$(error EMBED_SUBDIRS recursion limit reached...))

# embedding done, move variables back

$(eval $(call SetDirs,$(SUBLOC)))
CLEANFILES := $(am_CLEANFILES)
DISTCLEANFILES := $(am_DISTCLEANFILES)
MAINTAINERCLEANFILES := $(am_MAINTAINERCLEANFILES)
SUBDIRS := $(am_SUBDIRS)
DIST_SUBDIRS := $(am_DIST_SUBDIRS)
EMBED_SUBDIRS := $(am_EMBED_DONE)
am_CLEANFILES =
am_DISTCLEANFILES =
am_MAINTAINERCLEANFILES =
am_DIST_SUBDIRS =
am_SUBDIRS =
am_EMBED_DONE =

am_TARGETLISTS := $(sort $(am_TARGETLISTS))
am_EXTRA_TARGETLISTS := $(sort $(am_EXTRA_TARGETLISTS))

# avoid duplicate entries with am_TARGETLISTS
am_EXTRA_TARGETLISTS := $(filter-out $(am_TARGETLISTS),$(am_EXTRA_TARGETLISTS))

# allow seeing moved lists
AM_FLAGS += real

## EMBED_SUBDIRS end

##
## Launch target hooks
##

amdir = $(dir $(realpath $(filter %/antimake.mk antimake.mk,$(MAKEFILE_LIST))))

# 1-feat name
FeatFile = $(call JoinPath,$(amdir),amext-$(1).mk)


# 1- fname
LoadFeature = $(if $(wildcard $(call FeatFile,$(1))),$(eval include $(call FeatFile,$(1))),$(error Feature "$(call FeatFile,$(1))" is not available.))

$(foreach f,$(AM_FEATURES),$(call LoadFeature,$(f)))



$(eval $(foreach hook,$(AM_TARGET_HOOKS),$(call ForEachTarget,$(hook),$(am_TARGETLISTS))))
$(eval $(foreach hook,$(AM_TARGET_HOOKS),$(call ForEachTarget,$(hook),$(am_EXTRA_TARGETLISTS))))


##
## Now generate the rules
##

## check which target func to call
# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
MakeTarget = $(call $(if $(filter $(AM_BIG_PRIMARIES),$(3)),MakeBigTarget,MakeSmallTarget),$(1),$(2),$(3),$(4),$(5))

## process all targets in one list
# 1-list, 2-prim,3-dest,4-flags
MakeTargetList = $(foreach tgt,$($(1)),$(call MakeTarget,$(call CleanName,$(tgt)),$(tgt),$(2),$(3),$(4)))

## process all target lists
# 1=list names
ProcessTargets = $(call ForEachTarget,MakeTarget,$(1))

# process non-EXTRA targets
$(eval $(call ProcessTargets,$(am_TARGETLISTS)))

# process EXTRA_* last, they may already have been processed
$(eval $(call ProcessTargets,$(am_EXTRA_TARGETLISTS)))

##
## clean targets
##

clean:
ifdef CLEANFILES
	$(E) "CLEAN" $@
	$(Q) $(RM) -- $(CLEANFILES)
endif

distclean: clean
	$(E) "DISTCLEAN" $@
	$(Q) $(RM) -r -- $(OBJDIR)
ifdef DISTCLEANFILES
	$(Q) $(RM) -- $(DISTCLEANFILES)
endif

maintainer-clean: clean
	$(E) "MAINTAINERCLEAN" $@
	$(Q) $(RM) -r -- $(OBJDIR)
ifdef DISTCLEANFILES
	$(Q) $(RM) -- $(DISTCLEANFILES)
endif
ifdef MAINTAINERCLEANFILES
	$(Q) $(RM) -- $(MAINTAINERCLEANFILES)
endif


##
## actual subdir targets
##

# 1-dir
define MakeSubDir
	$(trace1)
	$(E) "MKDIR" "Create $(call JoinPath,$(SUBLOC),$(1))"
	$(Q) $(call MkDir,$(1))
	$(Q) $(call Printf,"include $(call UpDir,$(1))/$(srcdir)/$(1)/Makefile\n") \
		> $(1)/Makefile
endef

# 1-dir, 2-tgt
define SubTarget
	$(trace2)
	$(if $(wildcard $(1)/Makefile),,$(call MakeSubDir,$(1)))
	$(E) "-->" "$(call JoinPath,$(SUBLOC),$(1))"
	$(Q) $(MAKE) -C $(1) $(2)
	$(E) "<--" "$(call JoinPath,$(SUBLOC),$(1))"
endef

sub-all sub-install sub-uninstall sub-clean:
	$(foreach dir,$(SUBDIRS),$(call SubTarget,$(dir),$(subst sub-,,$@))$(NewLine))

# Avoid double dirs in DIST_SUBDIRS, without changing order
am_DISTDIRS = $(SUBDIRS) $(foreach dir,$(DIST_SUBDIRS),$(if $(filter $(dir),$(SUBDIRS)),,$(dir)))

sub-dist sub-distclean sub-maintainer-clean:
	$(foreach dir,$(am_DISTDIRS),$(call SubTarget,$(dir),$(subst sub-,,$@))$(NewLine))
.PHONY: sub-all sub-clean sub-install sub-dist sub-distclean sub-maintainer-clean


##
## actual dist targets
##

DistTarget = $(foreach fmt,$(1),dist-$(fmt))

AM_DIST_ALL ?= gzip bzip2 xz zip

AM_DIST_ALL_TGTS = $(call DistTarget,$(AM_DIST_ALL))
AM_DIST_DEF_TGTS = $(call DistTarget,$(AM_DIST_DEFAULT))

AM_FORMAT_gzip_EXT = tar.gz
AM_FORMAT_gzip_CMD = tar chof - $(AM_DIST_BASE) | gzip > $(AM_DIST_BASE).$(AM_FORMAT_gzip_EXT)
AM_FORMAT_bzip2_EXT = tar.bz2
AM_FORMAT_bzip2_CMD = tar chof - $(AM_DIST_BASE) | bzip2 > $(AM_DIST_BASE).$(AM_FORMAT_bzip2_EXT)
AM_FORMAT_xz_EXT = tar.xz
AM_FORMAT_xz_CMD = tar chof - $(AM_DIST_BASE) | xz > $(AM_DIST_BASE).$(AM_FORMAT_xz_EXT)
AM_FORMAT_zip_EXT = zip
AM_FORMAT_zip_CMD = zip -rq $(AM_DIST_BASE).$(AM_FORMAT_zip_EXT) $(AM_DIST_BASE)

# 1-name
define MakeDist
	$(E) "CHECK" $@
	$(Q) $(MAKE) -s am-check-distfiles
	$(E) "MKDIR" $(AM_DIST_BASE)
	$(Q) $(RM) -r -- $(AM_DIST_BASE) $(AM_DIST_BASE).$(AM_FORMAT_$(1)_EXT)
	$(Q) $(call MkDir,$(AM_DIST_BASE))
	$(E) "COPY" $(AM_DIST_BASE)
	$(Q) $(MAKE) -s am-show-distfiles | cpio -pmduL --quiet $(AM_DIST_BASE)
	$(E) "PACK" $(AM_DIST_BASE).$(AM_FORMAT_$(1)_EXT)
	$(Q) $(AM_FORMAT_$(1)_CMD)
	$(Q) $(RM) -r -- $(AM_DIST_BASE)
endef

.PHONY: dist $(AM_DIST_ALL_TGTS)
dist: $(AM_DIST_DEF_TGTS)
dist-all: $(AM_DIST_ALL_TGTS)
$(AM_DIST_ALL_TGTS):
	$(call MakeDist,$(subst dist-,,$@))

# show list of files that need to be in final archive
.PHONY: am-show-distfiles
am-show-distfiles:
	$(foreach dir,$(am_DISTDIRS),@$(MAKE) $(AM_MAKEFLAGS) --no-print-directory -C $(dir) $@ $(NewLine))
	$(foreach file,$(am_FINAL_DISTFILES),@$(call Printf,"$(call JoinPath,$(SUBLOC),$(file))\n") $(NewLine))

# do dependencies as separate step, in case building outputs anything
.PHONY: am-check-distfiles
am-check-distfiles: $(am_FINAL_DISTFILES)
	$(foreach dir,$(am_DISTDIRS),@$(MAKE) $(AM_MAKEFLAGS) -C $(dir) $@ $(NewLine))

##
## debug target
##

# 1=var
define AmDebugShow
$(if $($(1)),@$(call Printf,"$(1) = $($(1))\n"))
$(NewLine)
endef

# 1=cleantgt,2=rawtgt,3=prim,4=dest,5=flags
define AmDebugTarget
$(trace5)
$(foreach var,$(AM_DEBUG_TARGET_VARS),$(call AmDebugShow,$(1)_$(var)))
@$(call Printf,"\n")
endef

# func args: 1-var, 2-prim, 3-dest, 4-flags
CollectDests = $(filter-out noinst EXTRA,$(3))
AM_USED_DESTS = $(sort $(call ForEachList,CollectDests,$(am_TARGETLISTS)))

AM_DEBUG_VARS = GNUMAKE380 GNUMAKE381 GNUMAKE382 MAKEFILE_LIST \
		AM_LANGUAGES AM_FLAGS AM_DESTINATIONS \
		AM_ALL_TARGETS EXEEXT am_FINAL_DISTFILES \
		nosub_top_builddir nosub_top_srcdir \
		abs_top_srcdir abs_top_builddir \
		srcdir builddir top_srcdir top_builddir \
		SUBDIRS EMBED_SUBDIRS DIST_SUBDIRS \
		DISTFILES CLEANFILES DISTCLEANFILES MAINTAINERCLEANFILES
AM_DEBUG_TARGET_VARS = SOURCES OBJS LINKVAR DEST USUAL_OBJS USUAL_SRCS EXT FINAL \
		       $(AM_TARGET_VARIABLES)
AM_DEBUG_LANG_VARS = SRCEXTS
am-debug:
	@$(call Printf,"\n==== Global Variables ====\n")
	$(foreach var,$(AM_DEBUG_VARS),$(call AmDebugShow,$(var)))
	@$(call Printf,"\n==== Per-language Variables ====\n")
	$(foreach lg,$(AM_LANGUAGES),$(foreach var,$(AM_DEBUG_LANG_VARS),$(call AmDebugShow,AM_LANG_$(lg)_$(var))))
	@$(call Printf,"\n==== Per-target Variables ====\n")
	$(call ForEachTarget,AmDebugTarget,$(am_TARGETLISTS) $(am_EXTRA_TARGETLISTS))
	@$(call Printf,"\n==== Active install directories ====\n")
	$(foreach dst,$(AM_USED_DESTS),@$(call Printf,"  $(dst)dir = $($(dst)dir)\n" $(NewLine)))


##
## regtests for basic tools
##

AM_TESTS = 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
AM_TEST_1 = $(call Eq,a b c,a b c),$(call Eq,,),$(call Eq,a,aa),$(call Eq,a,a a)
AM_TEST_1_RES = true,true,,
AM_TEST_2 = $(call Neq,a,aa),$(call Neq,a,a)
AM_TEST_2_RES = true,
AM_TEST_3 = $(call CleanName,obj/foo-baz.x)
AM_TEST_3_RES = obj_foo_baz_x
AM_TEST_4 = $(call LastWord,a),$(call LastWord,a b c),$(call LastWord,)
AM_TEST_4_RES = a,c,
AM_TEST_5 = $(call ReplaceExts,.c .cpp X.foo,.o,s1.c s2.cpp s3X.foo s4.h)
AM_TEST_5_RES = s1.o s2.o s3.o
AM_TEST_5 = $(call LangList,foo.c c.foo),$(call LangList,foo.c c.foo f.cpp)
AM_TEST_5_RES = C,C CXX
AM_TEST_6 = $(call DetectLinkVar,foo.c c.foo),$(call DetectLinkVar,foo.c c.foo x.cpp),$(call DetectLinkVar,foo),$(call DetectLinkVar,)
AM_TEST_6_RES = AM_LANG_C_LINK,AM_LANG_CXX_LINK,AM_LANG_C_LINK,AM_LANG_C_LINK
AM_TEST_7 = $(call UpDir,foo)|$(call UpDir,)|$(call UpDir,.)|$(call UpDir,foo/bar)|$(call UpDir,a/b/c)|
AM_TEST_7_RES = ..|.|.|../..|../../..|
AM_TEST_8 = $(call JoinPath,.,.)|$(call JoinPath,,)|$(call JoinPath,a,.)|$(call JoinPath,.,b)|$(call JoinPath,a,b)|$(call JoinPath,a/b,../c)|$(call JoinPath,a/b,../../../c)
AM_TEST_8_RES = .||a|b|a/b|a/c|../c
define AM_TEST_9_EVAL
$(IFEQ) ($$(AM_TEST_9_RES),OK)
AM_TEST_9 = OK
$(ELSE)
AM_TEST_9 = fail
$(ENDIF)
endef
AM_TEST_9_RES = OK
$(eval $(AM_TEST_9_EVAL))
AM_TEST_10 = $(call CheckName,nobase_bin_PROGRAMS,PROGRAMS,bin,nobase)|$(call CheckName,a,a,,)|$(call CheckName,bin_bin_DATA,,bin bin,DATA)
AM_TEST_10_RES = nobase_bin_PROGRAMS|a|
AM_TEST_11_Show = $(4)-$(3)-$(2)
AM_TEST_11 = $(call ForEachList,AM_TEST_11_Show,bin_PROGRAMS foo_DATA baz_foo base_nobase_dist_nodist_DATA_PROGRAMS)
AM_TEST_11_RES = -bin-PROGRAMS --DATA -- base nobase dist nodist--DATA PROGRAMS
AM_TEST_12 = $(call RelocFlags,sub/dir,-I. -I./foo -Lfoo/bar -I/inc -L/lib -lfoo)
AM_TEST_12_RES = -Isub/dir -Isub/dir/foo -Lsub/dir/foo/bar -I/inc -L/lib -lfoo
AM_TEST_13 = $(call TargetNoDist,HEADERS,)|$(call TargetNoDist,HEADERS,nodist)|$(call TargetNoDist,PROGRAMS,)|$(call TargetNoDist,PROGRAMS,dist)
AM_TEST_13_RES = |true|PROGRAMS|
AM_TEST_14 = $(call ShellQuote,foo'bar\')|$(call ShellQuote,as!d' \\ $$foo)
AM_TEST_14_RES = 'foo'\''bar\'\'''|'as!d'\'' \\ $$foo'
AM_TEST_15 = $(call JoinPath,sub/dir,../foo) , \
	     $(call JoinPath,sub/dir,../../foo) , \
	     $(call JoinPath,sub/dir,../../../foo) , \
	     $(call JoinPath,sub/dir/,../foo) , \
	     $(call JoinPath,/,./foo) , \
	     $(call JoinPath,..,../foo) , \
	     $(call JoinPath,/foo,../baz) , \
	     $(call JoinPath,/foo,../../baz) , \
	     $(call JoinPath,foo/..,./foo)
AM_TEST_15_RES = sub/foo , foo , ../foo , sub/foo , /foo , ../../foo , /baz , /baz , foo/../foo
AM_TEST_16_EXT = .foo
AM_TEST_16 = $(call FinalTargetFile,prog,prog,PROGRAMS) | $(call FinalTargetFile,AM_TEST_16,AM_TEST_16,PROGRAMS)
AM_TEST_16_RES = prog$(EXEEXT) | AM_TEST_16.foo

AmTest = $(if $(call Eq,$($(1)),$($(2))),@$(call Printf,"$(1): OK\n"),@$(call Printf,"$(subst ",',$(1): FAIL: $($(1)) != $($(2))\n)"))$(NewLine)
am-test:
	$(Q) test "$(call Eq,a b c,a b c),$(call Eq,,),$(call Eq,a,aa),$(call Eq,a,a a)" = "true,true,,"
	$(foreach nr,$(AM_TESTS),$(call AmTest,AM_TEST_$(nr),AM_TEST_$(nr)_RES))

##
## help target
##

AmHelpNames = targets standalone internal config dests
.PHONY: help $(foreach n,$(AmHelpNames),help-$(n) help-$(n)-local)
$(foreach n,$(AmHelpNames),help-$(n)-local):
help: $(foreach n,$(AmHelpNames),help-$(n) help-$(n)-local)

# 1-var, 2-desc
AmConf = @$(call Printf,"  %-27s  %s=%s\n" $(call ShellQuote,$(2)) $(call ShellQuote,$(1)) $(call ShellQuote,$($(1))))

help-targets:
	@$(call Printf,"\n")
	@$(call Printf,"Main targets:\n")
	@$(call Printf,"  all                Build all targets (default)\n")
	@$(call Printf,"  install            Install files\n")
	@$(call Printf,"  dist               Create source archive\n")
	@$(call Printf,"  clean              Clean built files\n")
	@$(call Printf,"  distclean          Clean configured files\n")
	@$(call Printf,"  maintainer-clean   Delete anything that can be generated\n")

help-standalone:
	@$(call Printf,"\n")
	@$(call Printf,"Standalone targets:   (make -f antimake.mk)\n")
	@$(call Printf,"  show-location      Prints full path to antimake.mk (default)\n")
	@$(call Printf,"  show-config        Prints template config.mak.in\n")

help-internal:
	@$(call Printf,"\n")
	@$(call Printf,"Internal targets:\n")
	@$(call Printf,"  am-show-distfiles  Shows files that go into source archive\n")
	@$(call Printf,"  am-debug           Shows variables that affect the build\n")
	@$(call Printf,"  am-test            Regtest for internal functions\n")

help-config:
	@$(call Printf,"\n")
	@$(call Printf,"Config variables and their current values:\n")
	$(call AmConf,CC,C compiler)
	$(call AmConf,CFLAGS,C compiler flags)
	$(call AmConf,CPPFLAGS,C pre-processor flags)
	$(call AmConf,LDFLAGS,Linker flags)

help-dests:
	@$(call Printf,"\n")
	@$(call Printf,"Destinations for install [ prefix=$(prefix) ]:\n")
	$(foreach dst,$(AM_USED_DESTS),@$(call Printf,"  $(dst)dir = $($(dst)dir)\n") $(NewLine))

endif # O=empty
