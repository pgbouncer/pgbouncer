hba_test = executable('hba_test',
                      'hba_test.c',
                      '../src/hba.c',
                      '../src/util.c',
                      libusual_sources,
                      config_h,
                      build_by_default: false,
                      include_directories: ['..', '../include', '../lib'],
                      dependencies: [libevent, openssl, systemd],
                     )

libpq = dependency('libpq', required: false, disabler: true)

asynctest = executable('asynctest',
                       'asynctest.c',
                       libusual_sources,
                       config_h,
                       build_by_default: false,
                       include_directories: ['..', '../include', '../lib'],
                       dependencies: [libevent, libpq, systemd],
                      )

test('hba_test',
     hba_test,
     workdir: meson.project_source_root() / 'test',
    )
