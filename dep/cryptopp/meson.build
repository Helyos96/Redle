sources_cryptopp = [
	'3way.cpp',
	'adler32.cpp',
	'algebra.cpp',
	'algparam.cpp',
	'allocate.cpp',
	'arc4.cpp',
	'aria.cpp',
	'ariatab.cpp',
	'aria_simd.cpp',
	'asn.cpp',
	'authenc.cpp',
	'base32.cpp',
	'base64.cpp',
	'basecode.cpp',
	'bfinit.cpp',
	'blake2.cpp',
	'blake2b_simd.cpp',
	'blake2s_simd.cpp',
	'blowfish.cpp',
	'blumshub.cpp',
	'camellia.cpp',
	'cast.cpp',
	'casts.cpp',
	'cbcmac.cpp',
	'ccm.cpp',
	'chacha.cpp',
	'chachapoly.cpp',
	'chacha_avx.cpp',
	'chacha_simd.cpp',
	'cham.cpp',
	'cham_simd.cpp',
	'channels.cpp',
	'cmac.cpp',
	'cpu.cpp',
	'crc.cpp',
	'crc_simd.cpp',
	'cryptlib.cpp',
	'darn.cpp',
	'default.cpp',
	'des.cpp',
	'dessp.cpp',
	'dh.cpp',
	'dh2.cpp',
	'dll.cpp',
	'donna_32.cpp',
	'donna_64.cpp',
	'donna_sse.cpp',
	'dsa.cpp',
	'eax.cpp',
	'ec2n.cpp',
	'eccrypto.cpp',
	'ecp.cpp',
	'elgamal.cpp',
	'emsa2.cpp',
	'eprecomp.cpp',
	'esign.cpp',
	'files.cpp',
	'filters.cpp',
	'fips140.cpp',
	'gcm.cpp',
	'gcm_simd.cpp',
	'gf256.cpp',
	'gf2n.cpp',
	'gf2n_simd.cpp',
	'gf2_32.cpp',
	'gfpcrypt.cpp',
	'gost.cpp',
	'gzip.cpp',
	'hc128.cpp',
	'hc256.cpp',
	'hex.cpp',
	'hight.cpp',
	'hmac.cpp',
	'hrtimer.cpp',
	'ida.cpp',
	'idea.cpp',
	'integer.cpp',
	'iterhash.cpp',
	'kalyna.cpp',
	'kalynatab.cpp',
	'keccak.cpp',
	'keccak_core.cpp',
	'keccak_simd.cpp',
	'lea.cpp',
	'lea_simd.cpp',
	'lsh256.cpp',
	'lsh256_avx.cpp',
	'lsh256_sse.cpp',
	'lsh512.cpp',
	'lsh512_avx.cpp',
	'lsh512_sse.cpp',
	'luc.cpp',
	'mars.cpp',
	'marss.cpp',
	'md2.cpp',
	'md4.cpp',
	'md5.cpp',
	'misc.cpp',
	'modes.cpp',
	'mqueue.cpp',
	'mqv.cpp',
	'nbtheory.cpp',
	'neon_simd.cpp',
	'oaep.cpp',
	'osrng.cpp',
	'padlkrng.cpp',
	'panama.cpp',
	'pch.cpp',
	'pkcspad.cpp',
	'poly1305.cpp',
	'polynomi.cpp',
	'power7_ppc.cpp',
	'power8_ppc.cpp',
	'power9_ppc.cpp',
	'ppc_simd.cpp',
	'pssr.cpp',
	'pubkey.cpp',
	'queue.cpp',
	'rabbit.cpp',
	'rabin.cpp',
	'randpool.cpp',
	'rc2.cpp',
	'rc5.cpp',
	'rc6.cpp',
	'rdrand.cpp',
	'rdtables.cpp',
	'rijndael.cpp',
	'rijndael_simd.cpp',
	'ripemd.cpp',
	'rng.cpp',
	'rsa.cpp',
	'rw.cpp',
	'safer.cpp',
	'salsa.cpp',
	'scrypt.cpp',
	'seal.cpp',
	'seed.cpp',
	'serpent.cpp',
	'sha.cpp',
	'sha3.cpp',
	'shacal2.cpp',
	'shacal2_simd.cpp',
	'shake.cpp',
	'shark.cpp',
	'sharkbox.cpp',
	'sha_simd.cpp',
	'simeck.cpp',
	'simon.cpp',
	'simon128_simd.cpp',
	'simple.cpp',
	'skipjack.cpp',
	'sm3.cpp',
	'sm4.cpp',
	'sm4_simd.cpp',
	'sosemanuk.cpp',
	'speck.cpp',
	'speck128_simd.cpp',
	'square.cpp',
	'squaretb.cpp',
	'sse_simd.cpp',
	'strciphr.cpp',
	'tea.cpp',
	'tftables.cpp',
	'threefish.cpp',
	'tiger.cpp',
	'tigertab.cpp',
	'ttmac.cpp',
	'tweetnacl.cpp',
	'twofish.cpp',
	'vmac.cpp',
	'wake.cpp',
	'whrlpool.cpp',
	'xed25519.cpp',
	'xtr.cpp',
	'xtrcrypt.cpp',
	'xts.cpp',
	'zdeflate.cpp',
	'zinflate.cpp',
	'zlib.cpp',
]

cc = meson.get_compiler('c')
host_cpu_family = host_machine.cpu_family()

sources_cryptopp_asm = []
if host_cpu_family == 'x86'
	sources_cryptopp_asm += ['rdrand.asm', 'rdseed.asm']
elif host_cpu_family == 'x86_64'
	sources_cryptopp_asm += ['rdrand.asm', 'rdseed.asm', 'x64dll.asm', 'x64masm.asm']
endif

if cc.get_argument_syntax() == 'msvc'
  cl = find_program('cl')
  if host_cpu_family.startswith('x86')
    if host_cpu_family == 'x86'
      ml = find_program('ml')
	  assembler_args = [ml, '/Fo', '@OUTPUT@', '/c', '/D_M_X86', '/W3', '/Cx', '@INPUT@']
    elif host_cpu_family == 'x86_64'
      ml = find_program('ml64')
	  assembler_args = [ml, '/Fo', '@OUTPUT@', '/c', '/D_M_X64', '/W3', '/Cx', '@INPUT@']
    else
      error('Unknown cpu_family: ' + host_cpu_family)
    endif
    if get_option('buildtype').startswith('debug')
      assembler_args += ['/Zi']
    endif
  elif host_cpu_family == 'aarch64'
    assembler_args = [find_program('armasm64'), '-o', '@OUTPUT@', '@INPUT@']
    if get_option('buildtype').startswith('debug')
      assembler_args += ['-g']
    endif
  else
    error('Unsupported MSVC target: ' + host_cpu_family)
  endif
  ffi_asm_objs = []
  foreach asm_source : sources_cryptopp_asm
    obj_name = asm_source.underscorify() + '.obj'
    ffi_asm_objs += custom_target(obj_name,
        input : asm_source,
        output : obj_name,
        command : assembler_args)
  endforeach
  sources_cryptopp_asm = ffi_asm_objs
endif

cryptopp_lib = static_library('cryptopp', sources : [sources_cryptopp, sources_cryptopp_asm])
cryptopp = declare_dependency(link_with : cryptopp_lib)
