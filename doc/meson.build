mandir = get_option('mandir')

env = environment()
env.set('PACKAGE_VERSION', meson.project_version())

# The custom_target()s are named (first positional arg) so this builds on meson
# older than 0.60, which required a name.
pgbouncer_1_md = \
  custom_target('pgbouncer_1.md',
                output: 'pgbouncer_1.md',
                input: ['filter.py', 'frag-usage-man.md', 'usage.md'],
                command: [python, '@INPUT@'],
                capture: true,
                env: env,
               )

pgbouncer_5_md = \
  custom_target('pgbouncer_5.md',
                output: 'pgbouncer_5.md',
                input: ['filter.py', 'frag-config-man.md', 'config.md'],
                command: [python, '@INPUT@'],
                capture: true,
                env: env,
               )

custom_target('pgbouncer.1',
              output: 'pgbouncer.1',
              input: [pgbouncer_1_md],
              command: [pandoc, '-s', '-t', 'man', '-o', '@OUTPUT@', '@INPUT@'],
              install: true,
              install_dir: mandir / 'man1',
             )

custom_target('pgbouncer.5',
              output: 'pgbouncer.5',
              input: [pgbouncer_5_md],
              command: [pandoc, '-s', '-t', 'man', '-o', '@OUTPUT@', '@INPUT@'],
              install: true,
              install_dir: mandir / 'man5',
             )
