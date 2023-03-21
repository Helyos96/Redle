project('redle', ['c', 'cpp'], default_options : ['cpp_std=c++20'])

if host_machine.system() == 'windows'
  cryptopp = dependency('cryptopp')
else
  cryptopp = dependency('libcrypto++')
endif
incdir = include_directories('dep')

subdir('tools')
subdir('src')
