project('pgbouncer',
        ['c'],
        version: '1.25.2',
        license: 'ISC',
        # Kept in reach of the meson shipped by the distros we build on (the
        # oldest being RHEL 8's 0.58), so CI can install meson from the official
        # package repos rather than pip.
        meson_version: '>= 0.58.0',
        default_options: [
          # The C standard is left at the compiler default; the C11 requirement
          # is enforced by an explicit probe below (see AC_USUAL_C11), which only
          # adds a -std= flag when the default is not already C11.
          # warning_level=2 supplies -Wall -Wextra (the rest of the autoconf
          # WFLAGS set is added explicitly below).
          'warning_level=2',
        ],
)

cc = meson.get_compiler('c')
fs = import('fs')
windows = host_machine.system() == 'windows'

# ----------------------------------------------------------------------
# Require a C11-capable compiler (mirrors AC_USUAL_C11).
#
# Prefer the compiler's default mode so a newer default (e.g. gnu17) is kept;
# only add an explicit -std= flag when the default is not already C11. A genuine
# C11 mode is required, not just the underlying keywords: GCC accepts
# _Static_assert/_Alignof/_Generic as extensions even in pre-C11 modes, while
# glibc gates the <assert.h>/<stdalign.h> macros the code actually uses on
# __STDC_VERSION__ >= 201112L. So key the probe off that macro and also exercise
# the library macros themselves.
# ----------------------------------------------------------------------

c11_probe = '''
#include <assert.h>
#include <stdalign.h>
#if __STDC_VERSION__ < 201112L
#error "C11 mode is not enabled"
#endif
static_assert(1, "static assertions work");
_Noreturn void pgb_noret(void);
_Noreturn void pgb_noret(void) { for (;;) {} }
int main(void) {
    int x = 0;
    int g = _Generic(x, int: 1, default: 0);
    int a = (int) alignof(int);
    return g + a - g - a;
}
'''

c11_flag = ''
c11_ok = false
foreach flag : ['', '-std=gnu11', '-std=c11']
  label = flag == '' ? 'C11 support (compiler default)' : 'C11 support (@0@)'.format(flag)
  if cc.compiles(c11_probe, args: flag == '' ? [] : [flag], name: label)
    c11_ok = true
    c11_flag = flag
    break
  endif
endforeach

if not c11_ok
  error('a C11-capable compiler is required to build this software')
endif
if c11_flag != ''
  add_project_arguments(c11_flag, language: 'c')
endif

not_found_dep = dependency('', required: false)

cdata = configuration_data()

# ----------------------------------------------------------------------
# Package metadata (mirrors AC_INIT / config.mak.in)
# ----------------------------------------------------------------------

cdata.set_quoted('PACKAGE_NAME', 'PgBouncer')
cdata.set_quoted('PACKAGE_TARNAME', 'pgbouncer')
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('PACKAGE_STRING', 'PgBouncer @0@'.format(meson.project_version()))
cdata.set_quoted('PACKAGE_URL', 'https://www.pgbouncer.org/')
cdata.set_quoted('PACKAGE_BUGREPORT', 'https://github.com/pgbouncer/pgbouncer/issues')

# Windows resource files want the version as a comma separated 4-tuple.
version_parts = meson.project_version().split('.')
if version_parts.length() == 1
  version_parts += ['0', '0', '0']
elif version_parts.length() == 2
  version_parts += ['0', '0']
elif version_parts.length() == 3
  version_parts += ['0']
endif
cdata.set('PACKAGE_VERSION_4B', ','.join(version_parts),
          description: 'Version of this package for the Windows resource file (1,2,3,4).')

# ----------------------------------------------------------------------
# Basic environment defines (mirrors AC_USUAL_INIT / AC_USUAL_TYPE_CHECK)
# ----------------------------------------------------------------------

cdata.set('_GNU_SOURCE', 1,
          description: 'Define to get some GNU functions in headers.')
# Always request a 64-bit off_t. Harmless on 64-bit platforms and required on
# 32-bit ones (replaces autoconf's AC_SYS_LARGEFILE).
cdata.set('_FILE_OFFSET_BITS', 64)

if windows
  cdata.set('WIN32_LEAN_AND_MEAN', 1,
            description: 'Define to request cleaner win32 headers.')
  cdata.set('WINVER', '0x0600',
            description: 'Define to max win32 API version (0x0600=Vista).')
endif

if host_machine.endian() == 'big'
  cdata.set('WORDS_BIGENDIAN', 1,
            description: 'Define to 1 on big-endian hosts.')
endif

# pid_t/uid_t/gid_t fall back to int when the platform lacks them.
foreach t : [['pid_t', 'int'], ['uid_t', 'int'], ['gid_t', 'int']]
  if not cc.has_type(t[0], prefix: '#include <sys/types.h>')
    cdata.set(t[0], t[1])
  endif
endforeach

# ----------------------------------------------------------------------
# Header checks (mirrors AC_USUAL_HEADER_CHECK + pgbouncer extras)
# ----------------------------------------------------------------------

# The C89/C99 headers (stdio.h, string.h, stdint.h, ...) are guaranteed by the
# C11 requirement and their HAVE_ macros are no longer consulted anywhere, so
# only the genuinely platform-specific headers are probed, matching what
# configure's AC_USUAL_HEADER_CHECK still checks.
header_checks = [
  'arpa/inet.h',
  'byteswap.h',
  'dlfcn.h',
  'endian.h',
  'err.h',
  'fnmatch.h',
  'getopt.h',
  'grp.h',
  'langinfo.h',
  'linux/random.h',
  'malloc.h',
  'netdb.h',
  'netinet/in.h',
  'netinet/tcp.h',
  'poll.h',
  'pthread.h',
  'pwd.h',
  'regex.h',
  'syslog.h',
  'sys/endian.h',
  'sys/mman.h',
  'sys/param.h',
  'sys/resource.h',
  'sys/socket.h',
  'sys/time.h',
  'sys/uio.h',
  'sys/un.h',
  'sys/wait.h',
  'unistd.h',
  'xlocale.h',
]

foreach header : header_checks
  varname = 'HAVE_' + header.underscorify().to_upper()
  cdata.set(varname, cc.has_header(header) ? 1 : false,
            description: 'Define to 1 if you have the <@0@> header file.'.format(header))
endforeach

# ucred.h / sys/ucred.h have prerequisites on some platforms (sys/param.h on
# the BSDs, guarded by its check above since it does not exist everywhere).
ucred_prefix = '#include <sys/types.h>'
if cdata.get('HAVE_SYS_PARAM_H') == 1
  ucred_prefix += '\n#include <sys/param.h>'
endif

foreach header : ['ucred.h', 'sys/ucred.h']
  varname = 'HAVE_' + header.underscorify().to_upper()
  cdata.set(varname, cc.has_header(header, prefix: ucred_prefix) ? 1 : false,
            description: 'Define to 1 if you have the <@0@> header file.'.format(header))
endforeach

# ----------------------------------------------------------------------
# Function checks (mirrors AC_USUAL_FUNCTION_CHECK + pgbouncer extras)
# ----------------------------------------------------------------------

check_funcs = [
  'arc4random_buf',
  'asprintf',
  'err',
  'errx',
  'explicit_bzero',
  'ffs',
  'ffsl',
  'ffsll',
  'fls',
  'flsl',
  'flsll',
  'fnmatch',
  'getentropy',
  'getline',
  'getopt',
  'getopt_long',
  'getopt_long_only',
  'getpeereid',
  'getpeerucred',
  'getprogname',
  'getrandom',
  'getrusage',
  'gettimeofday',
  'inet_ntop',
  'inet_pton',
  'localtime_r',
  'lstat',
  'mbsnrtowcs',
  'memalign',
  'memmem',
  'mempcpy',
  'memrchr',
  'memset_s',
  'mmap',
  'nl_langinfo',
  'poll',
  'posix_memalign',
  'reallocarray',
  'recvmsg',
  'regcomp',
  'sendmsg',
  'setprogname',
  'sigaction',
  'sigqueue',
  'strlcat',
  'strlcpy',
  'strsep',
  'strtod_l',
  'strtonum',
  'syslog',
  'timegm',
  'usleep',
  'valloc',
  'vasprintf',
  'warn',
  'warnx',
]

foreach func : check_funcs
  cdata.set('HAVE_' + func.to_upper(), cc.has_function(func, args: '-D_GNU_SOURCE') ? 1 : false,
            description: 'Define to 1 if you have the `@0@\' function.'.format(func))
endforeach

# strerror_r: does it return char * (GNU) or int (XSI)? Only the return-type
# question matters; lib/usual/string.c assumes strerror_r itself exists.
strerror_r_char_p = cc.compiles('''
#define _GNU_SOURCE
#include <string.h>
int main(void) {
    char buf[100];
    char *p = strerror_r(0, buf, sizeof(buf));
    return !p;
}
''', name: 'strerror_r returns char *')
cdata.set('STRERROR_R_CHAR_P', strerror_r_char_p ? 1 : false,
          description: 'Define to 1 if strerror_r returns char *.')

# Native be/le enc/dec helpers (be16enc, le32dec, ...).
encdec_args = []
if cc.has_header('endian.h')
  encdec_args += '-DHAVE_ENDIAN_H'
endif
if cc.has_header('sys/endian.h')
  encdec_args += '-DHAVE_SYS_ENDIAN_H'
endif
have_encdec = cc.links('''
#include <sys/types.h>
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
char p[] = "01234567";
int main(void) {
    be16enc(p, 0); be32enc(p, 1); be64enc(p, 2);
    le16enc(p, 2); le32enc(p, 3); le64enc(p, 4);
    return (int)(be16dec(p) + be32dec(p) + be64dec(p)) +
           (int)(le16dec(p) + le32dec(p) + le64dec(p));
}
''', args: encdec_args, name: 'be/le enc/dec functions')
cdata.set('HAVE_ENCDEC_FUNCS', have_encdec ? 1 : false,
          description: 'Define if *enc & *dec functions are available.')

# ----------------------------------------------------------------------
# Threads (needed for PAM/LDAP and the getaddrinfo_a compat fallback)
# ----------------------------------------------------------------------

threads = dependency('threads')
cdata.set('HAVE_PTHREAD', cc.has_header('pthread.h') ? 1 : false)

# ----------------------------------------------------------------------
# assert checking (mirrors AC_USUAL_CASSERT / --enable-cassert)
# ----------------------------------------------------------------------

cdata.set('CASSERT', get_option('cassert') ? 1 : false,
          description: 'Define to enable assert checking.')

# ----------------------------------------------------------------------
# libevent (required)
# ----------------------------------------------------------------------

libevent = dependency('libevent')

# ----------------------------------------------------------------------
# OpenSSL / TLS (mirrors AC_USUAL_TLS)
# ----------------------------------------------------------------------

opensslopt = get_option('openssl')
openssl = dependency('openssl', required: opensslopt)
if openssl.found()
  cdata.set('USUAL_LIBSSL_FOR_TLS', 1, description: 'Use libssl for TLS.')
  cdata.set('OPENSSL_API_COMPAT', '0x00908000L',
            description: 'OpenSSL API version in use, to silence deprecation warnings.')

  # LibreSSL-only helpers, used when present.
  foreach func : ['SSL_CTX_use_certificate_chain_mem', 'SSL_CTX_load_verify_mem', 'asn1_time_parse']
    cdata.set('HAVE_' + func.to_upper(),
              cc.has_function(func, dependencies: openssl) ? 1 : false)
  endforeach

  # Pick a default root CA bundle, unless one was given explicitly.
  cafile = get_option('root_ca_file')
  if cafile == ''
    foreach candidate : [
      '/etc/ssl/certs/ca-certificates.crt',
      '/etc/pki/tls/certs/ca-bundle.crt',
      '/etc/ssl/ca-bundle.pem',
      '/etc/pki/tls/cacert.pem',
      '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
      '/etc/ssl/cert.pem',
    ]
      if cafile == '' and fs.is_file(candidate)
        cafile = candidate
      endif
    endforeach
    if cafile == ''
      cafile = '/etc/ssl/certs/ca-certificates.crt'
    endif
  endif
  cdata.set_quoted('USUAL_TLS_CA_FILE', cafile, description: 'Path to root CA certs.')
  message('root CA file: ' + cafile)
endif

# ----------------------------------------------------------------------
# systemd (mirrors --with-systemd)
# ----------------------------------------------------------------------

# libsystemd only exists on Linux; on other systems an `auto` lookup simply
# comes back not-found, so no special-casing is needed.
systemd = dependency('libsystemd', required: get_option('systemd'))
cdata.set('USE_SYSTEMD', systemd.found() ? 1 : false,
          description: 'Define to build with systemd support. (-Dsystemd=enabled)')

# ----------------------------------------------------------------------
# PAM (mirrors --with-pam)
# ----------------------------------------------------------------------

# pam/ldap are combo options ('auto'/'enabled'/'disabled') rather than meson
# `feature`s: the feature accessors (.allowed(), and passing a feature to
# find_library's `required`) need meson 0.59, newer than our floor. The string
# compare below reproduces the same semantics on older meson.
pamopt = get_option('pam')
pam = not_found_dep
if pamopt != 'disabled'
  pam = cc.find_library('pam', required: pamopt == 'enabled', has_headers: ['security/pam_appl.h'])
endif
if pam.found()
  cdata.set('HAVE_PAM', 1, description: 'PAM support.')
  cdata.set('HAVE_SECURITY_PAM_APPL_H', 1)
endif

# ----------------------------------------------------------------------
# LDAP (mirrors --with-ldap)
# ----------------------------------------------------------------------

ldapopt = get_option('ldap')
ldap = not_found_dep
if ldapopt != 'disabled'
  ldap = cc.find_library('ldap', required: ldapopt == 'enabled', has_headers: ['ldap.h'])
endif
if ldap.found()
  cdata.set('HAVE_LDAP', 1, description: 'LDAP support.')
  cdata.set('HAVE_LDAP_H', 1)
endif

# ----------------------------------------------------------------------
# DNS backend selection (mirrors the DNS section of configure.ac)
#
# Order of preference: c-ares, then libevent's evdns, then the libc /
# getaddrinfo_a based compat path. Exactly one USE_* macro is defined so that
# src/dnslookup.c selects a single implementation.
# ----------------------------------------------------------------------

caresopt = get_option('cares')
libcares = dependency('libcares', required: caresopt, version: '>= 1.9.0')

adns = ''
dns_deps = []
if libcares.found()
  adns = 'c-ares'
  cdata.set('USE_CARES', 1, description: 'Use c-ares for name resolution.')
  # Portability substitute for arpa/nameser.h, needed mainly for Windows.
  cdata.set('HAVE_ARES_NAMESER_H',
            cc.has_header('ares_nameser.h', dependencies: libcares) ? 1 : false)
elif get_option('evdns')
  adns = 'evdns'
  cdata.set('USE_EVDNS', 1, description: 'Use libevent for DNS lookups.')
else
  # Compat path: prefer glibc's native getaddrinfo_a, otherwise fall back to
  # the pthread-based implementation shipped in libusual (lib/usual/netdb.c).
  # getaddrinfo_a lives in libanl on older glibc and in libc since glibc 2.34,
  # so the library is optional but linked when present (AC_SEARCH_LIBS(..anl)).
  libanl = cc.find_library('anl', required: false)
  have_gaia = cc.links('''
#define _GNU_SOURCE
#include <stdio.h>
#include <netdb.h>
int main(void) {
#if defined(__GLIBC_PREREQ) && __GLIBC_PREREQ(2,9)
    getaddrinfo_a(0, NULL, 0, NULL);
    return 0;
#else
    return broken;
#endif
}
''', dependencies: libanl, name: 'native getaddrinfo_a')
  if have_gaia
    adns = 'libc'
    cdata.set('HAVE_GETADDRINFO_A', 1,
              description: 'Define to 1 if you have the getaddrinfo_a() function.')
    dns_deps = [libanl]
  else
    adns = 'compat (pthread)'
  endif
endif

# ----------------------------------------------------------------------
# Generate the config header.
#
# libusual normally includes <usual/config.h>; when USUAL_TEST_CONFIG is set it
# includes "test_config.h" instead (see lib/usual/base.h). We use that hook so
# the generated header lands in the build directory rather than the source tree.
# ----------------------------------------------------------------------

config_h = configure_file(output: 'test_config.h', configuration: cdata)
add_project_arguments('-DUSUAL_TEST_CONFIG', language: 'c')

# ----------------------------------------------------------------------
# Warning flags (mirrors the WFLAGS antimake enables)
# ----------------------------------------------------------------------

# Exact WFLAGS set the autoconf build selected (see AC_USUAL_* in lib/m4/usual.m4).
# Matching it matters because CI builds with -Werror (meson's -Dwerror=true), so a
# stricter set here would fail on warnings the autoconf build deliberately silenced
# (notably -Wno-missing-field-initializers). get_supported_arguments mirrors the
# per-flag compile probe autoconf does.
warning_flags = [
  # -Wall -Wextra come from warning_level=2 above.
  # turn off noise from -Wextra
  '-Wno-unused-parameter',
  '-Wno-missing-field-initializers',
  # things -Wextra does not turn on by itself
  '-Wmissing-prototypes',
  '-Wpointer-arith',
  '-Wendif-labels',
  '-Wdeclaration-after-statement',
  '-Wold-style-definition',
  '-Wstrict-prototypes',
  '-Wundef',
  '-Wformat=2',
  '-Wuninitialized',
  '-Wmissing-format-attribute',
]
add_project_arguments(cc.get_supported_arguments(warning_flags), language: 'c')

# ----------------------------------------------------------------------
# Sources
#
# The libusual file set matches what antimake's find_modules.sh selects for
# pgbouncer (i.e. the modules actually reached through #include <usual/...>).
# The TLS files are always compiled; their bodies are guarded by
# USUAL_LIBSSL_FOR_TLS and collapse to nothing when OpenSSL is disabled.
# ----------------------------------------------------------------------

libusual_sources = files(
  'lib/usual/aatree.c',
  'lib/usual/base.c',
  'lib/usual/cbtree.c',
  'lib/usual/cfparser.c',
  'lib/usual/crypto/chacha.c',
  'lib/usual/crypto/csrandom.c',
  'lib/usual/crypto/digest.c',
  'lib/usual/crypto/entropy.c',
  'lib/usual/crypto/keccak.c',
  'lib/usual/crypto/keccak_prng.c',
  'lib/usual/crypto/md5.c',
  'lib/usual/cxalloc.c',
  'lib/usual/cxextra.c',
  'lib/usual/err.c',
  'lib/usual/fileutil.c',
  'lib/usual/getopt.c',
  'lib/usual/list.c',
  'lib/usual/logging.c',
  'lib/usual/mbuf.c',
  'lib/usual/mempool.c',
  'lib/usual/netdb.c',
  'lib/usual/pgutil.c',
  'lib/usual/regex.c',
  'lib/usual/safeio.c',
  'lib/usual/signal.c',
  'lib/usual/slab.c',
  'lib/usual/socket.c',
  'lib/usual/socket_ntop.c',
  'lib/usual/socket_pton.c',
  'lib/usual/string.c',
  'lib/usual/strpool.c',
  'lib/usual/time.c',
  'lib/usual/tls/tls.c',
  'lib/usual/tls/tls_cert.c',
  'lib/usual/tls/tls_client.c',
  'lib/usual/tls/tls_compat.c',
  'lib/usual/tls/tls_config.c',
  'lib/usual/tls/tls_conninfo.c',
  'lib/usual/tls/tls_ocsp.c',
  'lib/usual/tls/tls_peer.c',
  'lib/usual/tls/tls_server.c',
  'lib/usual/tls/tls_util.c',
  'lib/usual/tls/tls_verify.c',
)

pgbouncer_sources = files(
  'src/admin.c',
  'src/client.c',
  'src/dnslookup.c',
  'src/hba.c',
  'src/janitor.c',
  'src/ldapauth.c',
  'src/loader.c',
  'src/main.c',
  'src/messages.c',
  'src/objects.c',
  'src/pam.c',
  'src/pktbuf.c',
  'src/pooler.c',
  'src/prepare.c',
  'src/proto.c',
  'src/sbuf.c',
  'src/scram.c',
  'src/server.c',
  'src/stats.c',
  'src/system.c',
  'src/takeover.c',
  'src/util.c',
  'src/varcache.c',
  'src/common/base64.c',
  'src/common/bool.c',
  'src/common/cryptohash.c',
  'src/common/hmac.c',
  'src/common/pgstrcasecmp.c',
  'src/common/saslprep.c',
  'src/common/scram-common.c',
  'src/common/sha2.c',
  'src/common/string.c',
  'src/common/unicode_norm.c',
  'src/common/wchar.c',
)

# Winsock and the IP helper API (linked via LIBS in the autoconf build). Needed
# by anything that pulls in libusual's socket/tls code, including the test
# binaries in test/meson.build, so keep it in a shared variable.
net_deps = []
if windows
  net_deps += cc.find_library('ws2_32')
  net_deps += cc.find_library('iphlpapi')
endif

pgbouncer_deps = [
  libcares,
  libevent,
  openssl,
  systemd,
  pam,
  ldap,
  threads,
] + dns_deps + net_deps

# '.' brings in the build root (where the generated test_config.h lives).
incdir_names = ['.', 'include', 'lib'] + (windows ? ['win32'] : [])
pgbouncer_incdirs = include_directories(incdir_names)

if windows
  pgbouncer_sources += files('win32/win32support.c')
  win = import('windows')
  # win32ver.rc includes the generated config, so windres needs the same
  # USUAL_TEST_CONFIG define the C sources get.
  pgbouncer_sources += win.compile_resources('win32/win32ver.rc',
                                             include_directories: pgbouncer_incdirs,
                                             args: ['-DUSUAL_TEST_CONFIG'])
endif

pgbouncer = executable('pgbouncer',
  pgbouncer_sources,
  libusual_sources,
  config_h,
  include_directories: pgbouncer_incdirs,
  dependencies: pgbouncer_deps,
  install: true,
)

# ----------------------------------------------------------------------
# win32 event log helper (pgbevent.dll)
# ----------------------------------------------------------------------

if windows
  pgbevent_res = win.compile_resources('win32/eventmsg.rc',
                                       include_directories: pgbouncer_incdirs)
  shared_library('pgbevent',
    'win32/pgbevent.c',
    pgbevent_res,
    name_prefix: '',
    include_directories: pgbouncer_incdirs,
    install: true,
  )
endif

# ----------------------------------------------------------------------
# Tools needed for docs and tests
# ----------------------------------------------------------------------

python = find_program('python3', 'python', required: true)
pandoc = find_program('pandoc', required: false, native: true)

# ----------------------------------------------------------------------
# Docs and data installation
# ----------------------------------------------------------------------

if pandoc.found()
  subdir('doc')
else
  message('pandoc not found: man pages will not be built or installed')
endif

pkgdocdir = get_option('datadir') / 'doc' / 'pgbouncer'

install_data(
  'README.md',
  'NEWS.md',
  'etc/pgbouncer-minimal.ini',
  'etc/pgbouncer.ini',
  'etc/pgbouncer.service',
  'etc/pgbouncer.socket',
  'etc/userlist.txt',
  install_dir: pkgdocdir,
)

# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

subdir('test')

test('optscan',
     files('etc/optscan.sh'),
     workdir: meson.project_source_root())

# Pick the binary used to run the test suite. An explicit -Dpytest=... wins;
# otherwise prefer the `pytest` console script and fall back to `python -m
# pytest`.
pytest_opt = get_option('pytest')
pytest_args = []
if pytest_opt != ''
  pytest_exe = find_program(pytest_opt)
else
  pytest = find_program('pytest', required: false)
  if pytest.found()
    pytest_exe = pytest
  else
    pytest_exe = python
    pytest_args = ['-m', 'pytest']
  endif
endif
pytest_args += ['-n', 'auto', '-r', 's']

test('pytest',
     pytest_exe,
     args: pytest_args,
     env: {
       'BOUNCER_EXE': pgbouncer.full_path(),
       'PYTHONIOENCODING': 'utf8',
     },
     workdir: meson.project_source_root() / 'test',
     depends: [pgbouncer],
     timeout: 1000,
    )

# ----------------------------------------------------------------------
# Convenience developer targets (mirrors the Makefile phony targets)
# ----------------------------------------------------------------------

# Formatting and linting are handled by a standalone script so they do not
# depend on the build system (dev/format.sh builds the pinned uncrustify and
# drives ruff). These targets mirror the old `make format`/`format-check`/`lint`.
format_sh = find_program('dev/format.sh')
run_target('format', command: [format_sh, 'fix'])
run_target('format-check', command: [format_sh, 'check'])
run_target('lint', command: [format_sh, 'lint'])

ctags = find_program('ctags', required: false)
if ctags.found()
  run_target('tags',
             command: [ctags, '-R', 'src', 'include', 'lib/usual'])
endif

# ----------------------------------------------------------------------
# Configuration summary
# ----------------------------------------------------------------------

summary({
  'adns': adns,
  'ldap': ldap.found(),
  'pam': pam.found(),
  'systemd': systemd.found(),
  'tls': openssl.found(),
  'cassert': get_option('cassert'),
}, section: 'PgBouncer')
