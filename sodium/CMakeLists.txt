add_library(sodium STATIC)

target_include_directories(sodium PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

#target_sources(sodium PRIVATE 
#							sodium.h
#							sodium_blake2.h
#							sodium_blake2b-compress-avx2.h
#							sodium_blake2b-compress-sse41.h
#							sodium_blake2b-compress-ssse3.h
#							sodium_blake2b-load-avx2.h
#							sodium_blake2b-load-sse2.h
#							sodium_blake2b-load-sse41.h
#							sodium_common.h
#							sodium_core.h
#							sodium_crypto_aead_chacha20poly1305.h
#							sodium_crypto_aead_xchacha20poly1305.h
#							sodium_crypto_auth.h
#							sodium_crypto_auth_hmacsha512.h
#							sodium_crypto_auth_hmacsha512256.h
#							sodium_crypto_box.h
#							sodium_crypto_box_curve25519xchacha20poly1305.h
#							sodium_crypto_box_curve25519xsalsa20poly1305.h
#							sodium_crypto_core_ed25519.h
#							sodium_crypto_core_hchacha20.h
#							sodium_crypto_core_hsalsa20.h
#							sodium_crypto_core_salsa20.h
#							sodium_crypto_core_salsa2012.h
#							sodium_crypto_core_salsa208.h
#							sodium_crypto_generichash.h
#							sodium_crypto_generichash_blake2b.h
#							sodium_crypto_hash.h
#							sodium_crypto_hash_sha256.h
#							sodium_crypto_hash_sha512.h
#							sodium_crypto_kx.h
#							sodium_crypto_onetimeauth.h
#							sodium_crypto_onetimeauth_poly1305.h
#							sodium_crypto_scalarmult.h
#							sodium_crypto_scalarmult_curve25519.h
#							sodium_crypto_scalarmult_ed25519.h
#							sodium_crypto_secretbox.h
#							sodium_crypto_secretbox_xchacha20poly1305.h
#							sodium_crypto_secretbox_xsalsa20poly1305.h
#							sodium_crypto_secretstream_xchacha20poly1305.h
#							sodium_crypto_shorthash.h
#							sodium_crypto_shorthash_siphash24.h
#							sodium_crypto_sign.h
#							sodium_crypto_sign_ed25519.h
#							sodium_crypto_sign_edwards25519sha512batch.h
#							sodium_crypto_stream.h
#							sodium_crypto_stream_chacha20.h
#							sodium_crypto_stream_salsa20.h
#							sodium_crypto_stream_salsa2012.h
#							sodium_crypto_stream_salsa208.h
#							sodium_crypto_stream_xchacha20.h
#							sodium_crypto_stream_xsalsa20.h
#							sodium_crypto_verify_16.h
#							sodium_crypto_verify_32.h
#							sodium_crypto_verify_64.h
#							sodium_dolbeau_chacha20-avx2.h
#							sodium_dolbeau_chacha20-ssse3.h
#							sodium_dolbeau_u0.h
#							sodium_dolbeau_u1.h
#							sodium_dolbeau_u4.h
#							sodium_dolbeau_u8.h
#							sodium_export.h
#							sodium_fe_25_5_base.h
#							sodium_fe_25_5_base2.h
#							sodium_fe_25_5_constants.h
#							sodium_fe_25_5_fe.h
#							sodium_fe_51_base.h
#							sodium_fe_51_base2.h
#							sodium_fe_51_constants.h
#							sodium_fe_51_fe.h
#							sodium_onetimeauth_poly1305.h
#							sodium_poly1305-sse2.h
#							sodium_poly1305_donna.h
#							sodium_poly1305_donna32.h
#							sodium_poly1305_donna64.h
#							sodium_private_chacha20_ietf_ext.h
#							sodium_private_common.h
#							sodium_private_ed25519_ref10.h
#							sodium_private_ed25519_ref10_fe_25_5.h
#							sodium_private_ed25519_ref10_fe_51.h
#							sodium_private_implementations.h
#							sodium_private_mutex.h
#							sodium_private_sse2_64_32.h
#							sodium_randombytes.h
#							sodium_randombytes_nativeclient.h
#							sodium_randombytes_salsa20_random.h
#							sodium_randombytes_sysrandom.h
#							sodium_ref10_sign_ed25519.h
#							sodium_ref10_x25519.h
#							sodium_runtime.h
#							sodium_salsa20-ref.h
#							sodium_salsa20-xmm6.h
#							sodium_sandy2x_consts_namespace.h
#							sodium_sandy2x_curve25519.h
#							sodium_sandy2x_fe.h
#							sodium_sandy2x_fe51.h
#							sodium_sandy2x_fe51_namespace.h
#							sodium_sandy2x_ladder.h
#							sodium_sandy2x_ladder_base.h
#							sodium_sandy2x_ladder_base_namespace.h
#							sodium_sandy2x_ladder_namespace.h
#							sodium_utils.h
#							sodium_version.h
#							sodium_xmm6int_salsa20-avx2.h
#							sodium_xmm6int_salsa20-sse2.h
#							sodium_xmm6int_u0.h
#							sodium_xmm6int_u1.h
#							sodium_xmm6int_u4.h
#							sodium_xmm6int_u8.h)

target_sources(sodium PRIVATE
							src/sodium_aead_chacha20poly1305.c
							src/sodium_aead_xchacha20poly1305.c
							src/sodium_blake2b-compress-avx2.c
							src/sodium_blake2b-compress-ref.c
							src/sodium_blake2b-compress-sse41.c
							src/sodium_blake2b-compress-ssse3.c
							src/sodium_blake2b-ref.c
							src/sodium_box_curve25519xchacha20poly1305.c
							src/sodium_box_curve25519xsalsa20poly1305.c
							src/sodium_box_seal_curve25519xchacha20poly1305.c
							src/sodium_chacha20-ref.c
							src/sodium_codecs.c
							src/sodium_core.c
							src/sodium_core_ed25519.c
							src/sodium_core_hchacha20.c
							src/sodium_core_hsalsa20.c
							src/sodium_core_hsalsa20_ref2.c
							src/sodium_core_salsa_ref.c
							src/sodium_crypto_box.c
							src/sodium_crypto_box_easy.c
							src/sodium_crypto_generichash.c
							src/sodium_crypto_hash_sha256.c
							src/sodium_crypto_hash_sha256_cp.c
							src/sodium_crypto_kx.c
							src/sodium_crypto_scalarmult.c
							src/sodium_crypto_secretbox.c
							src/sodium_crypto_secretbox_easy.c
							src/sodium_crypto_sign.c
							src/sodium_dolbeau_chacha20-avx2.c
							src/sodium_dolbeau_chacha20-ssse3.c
							src/sodium_generichash_blake2.c
							src/sodium_generichash_blake2b.c
							src/sodium_hash_sha512.c
							src/sodium_hash_sha512_cp.c
							src/sodium_onetimeauth_poly1305.c
							src/sodium_poly1305-sse2.c
							src/sodium_poly1305_donna.c
							src/sodium_randombytes.c
							src/sodium_randombytes_salsa20_random.c
							src/sodium_randombytes_sysrandom.c
							src/sodium_ref10_ed25519.c
							src/sodium_ref10_keypair.c
							src/sodium_ref10_open.c
							src/sodium_ref10_scalarmult_ed25519_ref10.c
							src/sodium_ref10_sign.c
							src/sodium_ref10_x25519.c
							src/sodium_runtime.c
							src/sodium_salsa20-ref.c
							src/sodium_salsa20-xmm6.c
							src/sodium_sandy2x_fe51_invert.c
							src/sodium_sandy2x_fe_frombytes.c
							src/sodium_scalarmult_curve25519.c
							src/sodium_sandy2x_curve25519.c
							src/sodium_secretbox_xchacha20poly1305.c
							src/sodium_secretbox_xsalsa20poly1305.c
							src/sodium_sign_ed25519.c
							src/sodium_stream_chacha20.c
							src/sodium_stream_salsa20.c
							src/sodium_stream_xchacha20.c
							src/sodium_stream_xsalsa20.c
							src/sodium_utils.c
							src/sodium_verify.c
							src/sodium_version.c
							src/sodium_xmm6int_salsa20-avx2.c
							src/sodium_xmm6int_salsa20-sse2.c)

# Platform-specific assembly files, not win32 and x86_64
if(NOT WIN32 AND ${CMAKE_SIZEOF_VOID_P} MATCHES 8)
	set_source_files_properties(
							src/sodium_salsa20-xmm6_asm.S 
							src/sodium_sandy2x.S 
							src/sodium_sandy2x_consts.S 
							src/sodium_sandy2x_fe51_mul.S 
							src/sodium_sandy2x_fe51_nsquare.S 
							src/sodium_sandy2x_fe51_pack.S 
							src/sodium_sandy2x_ladder.S 
							src/sodium_sandy2x_ladder_base.S
							PROPERTIES LANGUAGE C)

    target_sources(sodium PRIVATE
							src/sodium_salsa20-xmm6_asm.S
							src/sodium_sandy2x.S
							src/sodium_sandy2x_consts.S
							src/sodium_sandy2x_fe51_mul.S
							src/sodium_sandy2x_fe51_nsquare.S
							src/sodium_sandy2x_fe51_pack.S
							src/sodium_sandy2x_ladder.S
							src/sodium_sandy2x_ladder_base.S)
endif()

target_compile_definitions(sodium PRIVATE NEXT_CRYPTO_LOGS=1)

target_compile_definitions(sodium PRIVATE 
    $<$<BOOL:${CMAKE_SIZEOF_VOID_P} MATCHES 8>:NEXT_X64>
    $<$<BOOL:${CMAKE_SIZEOF_VOID_P} MATCHES 4>:NEXT_X86=1>
)

 target_compile_options(sodium PRIVATE
   $<$<CXX_COMPILER_ID:MSVC>:/arch:AVX2>
   $<$<CXX_COMPILER_ID:GNU>:-mavx2>
   $<$<CXX_COMPILER_ID:Clang>:-mavx2>
 )

 target_compile_options(sodium PRIVATE
   $<$<CXX_COMPILER_ID:Clang>:-mssse3 -msse4.1>
 )
target_compile_options(sodium PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/GR->
  $<$<CXX_COMPILER_ID:GNU>:-fno-rtti>
  $<$<CXX_COMPILER_ID:Clang>:-fno-rtti>
)

target_compile_definitions(sodium PRIVATE NEXT_AVX=1 NEXT_AVX2=1)

if(MSVC)
    target_compile_options(sodium PRIVATE /wd4100 /wd4221 /wd4244 /wd4715 /wd4197 /wd4146 /wd4324 /wd4456 /wd4100 /wd4459 /wd4245)
	#target_add_link_options(/ignore:4221)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(sodium PRIVATE
        -Wno-unused-parameter
        -Wno-unused-function
        -Wno-unknown-pragmas
        -Wno-unused-variable
        -Wno-type-limits
    )
endif()
