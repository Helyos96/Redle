project('redle', ['c', 'cpp'], default_options : ['cpp_std=c++20'])

cryptopp = dependency('cryptopp')

compiler = meson.get_compiler('cpp')
dep = compiler.find_library('ws2_32', required: true)

executable('redle', 'main.cpp', 'ByteBuffer.cpp', 'fmt/format.cc', 'fmt/os.cc', dependencies : [cryptopp, dep])
executable('dsa_key_gen', 'dsa_key_gen.cpp', dependencies : [cryptopp])
executable('testa', 'test.cpp', dependencies : [cryptopp])
executable('launcher', 'launcher.c')

