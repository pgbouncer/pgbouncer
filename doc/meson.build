mandir = get_option('mandir')

env = environment()
env.set('PACKAGE_VERSION', meson.project_version())

pgbouncer_1_md = \
  custom_target(output: 'pgbouncer_1.md',
                input: ['filter.py', 'frag-usage-man.md', 'usage.md'],
                command: [python, '@INPUT@'],
                capture: true,
                env: env,
               )

pgbouncer_5_md = \
  custom_target(output: 'pgbouncer_5.md',
                input: ['filter.py', 'frag-config-man.md', 'config.md'],
                command: [python, '@INPUT@'],
                capture: true,
                env: env,
               )

custom_target(output: 'pgbouncer.1',
              input: [pgbouncer_1_md],
              command: [pandoc, '-s', '-t', 'man', '-o', '@OUTPUT@', '@INPUT@'],
              install: true,
              install_dir: mandir / 'man1',
             )

custom_target(output: 'pgbouncer.5',
              input: [pgbouncer_5_md],
              command: [pandoc, '-s', '-t', 'man', '-o', '@OUTPUT@', '@INPUT@'],
              install: true,
              install_dir: mandir / 'man5',
             )
