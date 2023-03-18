project('redle', ['c', 'cpp'], default_options : ['cpp_std=c++20'])

cryptopp = dependency('cryptopp')
incdir = include_directories('dep')

fmt_lib = static_library('fmt', sources : ['dep/fmt/format.cc', 'dep/fmt/os.cc'])
fmt_dep = declare_dependency(link_with : fmt_lib)

subdir('tools')
subdir('src')
