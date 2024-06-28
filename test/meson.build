hba_test = executable('hba_test',
                      'hba_test.c',
                      '../src/hba.c',
                      '../src/util.c',
                      libusual_sources,
                      config_h,
                      include_directories: ['..', '../include', '../lib', '../uthash/src'],
                      dependencies: [libevent, openssl],
                     )

libpq = dependency('libpq', required: false, disabler: true)

asynctest = executable('asynctest',
                       'asynctest.c',
                       libusual_sources,
                       config_h,
                       include_directories: ['..', '../include', '../lib', '../uthash/src'],
                       dependencies: [libevent, libpq],
                      )

test('hba_test',
     hba_test,
     workdir: meson.source_root() / 'test',
    )
