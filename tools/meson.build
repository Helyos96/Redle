executable('dsa_key_gen', 'dsa_key_gen.cpp', dependencies : [cryptopp], include_directories : incdir)

if host_machine.system() == 'windows'
  executable('testa', 'test.cpp', dependencies : [cryptopp], include_directories : incdir)
  executable('launcher', 'launcher.c', 'shared.c')
  executable('obs', 'packet_dumper.c', 'shared.c')
endif
