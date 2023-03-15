project('redle', ['c', 'cpp'], default_options : ['cpp_std=c++20'])

cryptopp = dependency('cryptopp')

executable('redle', 'main.cpp', 'PacketHandlers.cpp', 'utils.cpp', 'ByteBuffer.cpp', 'fmt/format.cc', 'fmt/os.cc', dependencies : [cryptopp])
executable('dsa_key_gen', 'tools/dsa_key_gen.cpp', dependencies : [cryptopp])
executable('testa', 'tools/test.cpp', dependencies : [cryptopp])

if host_machine.system() == 'windows'
	executable('launcher', 'tools/launcher.c')
endif

