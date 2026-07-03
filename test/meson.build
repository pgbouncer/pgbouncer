# The '..' include dir also brings in the build root (its build-tree
# counterpart), which is where the generated test_config.h lives.
test_incdirs = include_directories('..', '../include', '../lib')

hba_test = executable('hba_test',
                      'hba_test.c',
                      '../src/hba.c',
                      '../src/util.c',
                      libusual_sources,
                      config_h,
                      build_by_default: false,
                      include_directories: test_incdirs,
                      dependencies: [libevent, openssl, systemd, threads] + net_deps,
                     )

libpq = dependency('libpq', required: false, disabler: true)

asynctest = executable('asynctest',
                       'asynctest.c',
                       libusual_sources,
                       config_h,
                       build_by_default: false,
                       include_directories: test_incdirs,
                       dependencies: [libevent, libpq, systemd, threads] + net_deps,
                      )

test('hba_test',
     hba_test,
     workdir: meson.project_source_root() / 'test',
    )
