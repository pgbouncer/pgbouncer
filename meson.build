project('PgBouncer',
        ['c'],
        version: '1.24.1',
        license: 'ISC',
)

cc = meson.get_compiler('c')

not_found_dep = dependency('', required: false)

cdata = configuration_data()


libcares = dependency('libcares', required: false)
libevent = dependency('libevent', required: true)
openssl = dependency('openssl', required: false)

#
# cares option
#
libcares = not_found_dep
caresopt = get_option('cares')
libcares = dependency('libcares', required: caresopt, version: '>= 1.6.0')
cdata.set('USE_CARES', libcares.found() ? 1 : false,
          description: 'Use c-ares for name resolution.')

#
# systemd option
#
systemd = not_found_dep
systemdopt = get_option('systemd')
systemdopt = systemdopt.disable_auto_if(host_machine.system() != 'linux')
systemd = dependency('libsystemd', required: systemdopt)
cdata.set('USE_SYSTEMD', systemd.found() ? 1 : false,
          description: 'Define to build with systemd support. (-Dsystemd=enabled)')


cdata.set('_GNU_SOURCE', 1,
          description: 'Define to get some GNU functions in headers.')

cdata.set('CASSERT', get_option('cassert') ? 1 : false,
          description: 'Define to enable assert checking')

check_funcs = [
  'arc4random_buf',
  'getentropy',
  'getopt',
  'getopt_long',
  'getrandom',
  'inet_ntop',
  'inet_pton',
  'lstat',
  'poll',
  'regcomp',
  'sigaction',
  'strerror_r',
  'strlcpy',
]

foreach func : check_funcs
  found = cc.has_function(func)
  cdata.set('HAVE_' + func.to_upper(), found ? 1 : false,
           description: 'Define to 1 if you have the `@0@\' function.'.format(func))
endforeach

cdata.set('HAVE_PTHREAD', 1)

header_checks = [
  'arpa/inet.h',
  'getopt.h',
  'grp.h',
  'netdb.h',
  'netinet/in.h',
  'netinet/tcp.h',
  'poll.h',
  'pthread.h',
  'pwd.h',
  'regex.h',
  'syslog.h',
  'sys/param.h',
  'sys/resource.h',
  'sys/socket.h',
  'sys/time.h',
  'sys/types.h',
  'sys/ucred.h',
  'sys/un.h',
  'ucred.h',
  'unistd.h',
]

foreach header : header_checks
  varname = 'HAVE_' + header.underscorify().to_upper()

  found = cc.has_header(header)
  cdata.set(varname, found ? 1 : false,
            description: 'Define to 1 if you have the <@0@> header file.'.format(header))
endforeach

cdata.set('OPENSSL_API_COMPAT', '0x00908000L',
          description: 'Define to the OpenSSL API version in use. This avoids deprecation warnings from newer OpenSSL versions.')
cdata.set('USUAL_LIBSSL_FOR_TLS', 1)
cdata.set_quoted('USUAL_TLS_CA_FILE', get_option('root-ca-file'))

cdata.set_quoted('PACKAGE_BUGREPORT', 'https://github.com/pgbouncer/pgbouncer/issues',
                 description: 'Define to the address where bug reports for this package should be sent.')
cdata.set_quoted('PACKAGE_NAME', meson.project_name(),
                 description: 'Define to the full name of this package.')
cdata.set_quoted('PACKAGE_STRING', '@0@ @1@'.format(meson.project_name(), meson.project_version()),
                 description: 'Define to the full name and version of this package.')
cdata.set_quoted('PACKAGE_URL', 'https://www.pgbouncer.org/',
                 description: 'Define to the home page for this package.')
cdata.set_quoted('PACKAGE_VERSION', meson.project_version(),
                 description: 'Define to the version of this package.')

cdata.set('USE_CARES', 1)


# FIXME: cannot write 'lib/usual/config.h' here
config_h = configure_file(output: 'test_config.h',
                          configuration: cdata,
                         )
add_project_arguments('-DUSUAL_TEST_CONFIG', language: ['c'])


cc = meson.get_compiler('c')

libusual_sources = files(
  'lib/usual/aatree.c',
  'lib/usual/base.c',
  'lib/usual/cbtree.c',
  'lib/usual/cfparser.c',
  'lib/usual/cxalloc.c',
  'lib/usual/cxextra.c',
  'lib/usual/err.c',
  'lib/usual/fileutil.c',
  'lib/usual/logging.c',
  'lib/usual/mbuf.c',
  'lib/usual/pgutil.c',
  'lib/usual/safeio.c',
  'lib/usual/slab.c',
  'lib/usual/socket.c',
  'lib/usual/string.c',
  'lib/usual/strpool.c',
  'lib/usual/time.c',
  'lib/usual/crypto/csrandom.c',
  'lib/usual/crypto/keccak.c',
  'lib/usual/crypto/keccak_prng.c',
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

pgbouncer = executable('pgbouncer',
           'src/admin.c',
           'src/client.c',
           'src/dnslookup.c',
           'src/hba.c',
           'src/janitor.c',
           'src/ldapauth.c',
           'src/loader.c',
           'src/messages.c',
           'src/main.c',
           'src/objects.c',
           'src/pam.c',
           'src/pktbuf.c',
           'src/pooler.c',
           'src/proto.c',
           'src/prepare.c',
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
           libusual_sources,
           config_h,

           include_directories: ['include', 'lib'],
           install: true,
           dependencies: [libcares, libevent, openssl, systemd],
)

pandoc = find_program('pandoc', required: true, native: true)
python = find_program('python3', 'python', required: true, native: true)

subdir('doc')

pkgdocdir = get_option('datadir') / 'doc' / 'pgbouncer'

install_data('README.md',
             'NEWS.md',
             'etc/pgbouncer-minimal.ini',
             'etc/pgbouncer.ini',
             'etc/pgbouncer.service',
             'etc/pgbouncer.socket',
             'etc/userlist.txt',
             install_dir: pkgdocdir)

test('optscan',
     files('etc/optscan.sh'),
     workdir: meson.project_source_root())

test('pytest',
     python,
     args: ['-m', 'pytest', '-n', 'auto', '-v', '..'],
     env: {
            'BOUNCER_EXE': pgbouncer.full_path(),
            'PYTHONIOENCODING': 'utf8',
            'TEST_USE_LDAP': '',
            'TEST_USE_TLS': '1',
          },
     depends: [pgbouncer],
     timeout: 1000,
    )

subdir('test')
