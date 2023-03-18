executable('dsa_key_gen', 'dsa_key_gen.cpp', dependencies : [cryptopp])

if host_machine.system() == 'windows'
  executable('testa', 'test.cpp', dependencies : [cryptopp])
  executable('launcher', 'launcher.c')
  executable('obs', 'packet_dumper.c')
endif
