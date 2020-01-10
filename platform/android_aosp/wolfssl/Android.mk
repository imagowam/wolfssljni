LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libwolfssl
LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_CFLAGS:= -DWOLFSSL_JNI -DWOLFSSL_DTLS -DOPENSSL_EXTRA -DHAVE_CRL -DHAVE_OCSP -DHAVE_CRL_MONITOR -DPERSIST_SESSION_CACHE -DPERSIST_CERT_CACHE -DATOMIC_USER -DHAVE_ECC -DTFM_ECC256 -DHAVE_PK_CALLBACKS -DHAVE_DH -DWOLFSSL_CERT_EXT -DWOLFSSL_CERT_GEN -DUSE_FAST_MATH -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DHAVE_TLS_EXTENSIONS -DHAVE_SNI -DHAVE_MAX_FRAGMENT -DHAVE_TRUNCATED_HMAC -DHAVE_ALPN -DHAVE_TRUSTED_CA -DHAVE_SUPPORTED_CURVES -Os -fomit-frame-pointer
LOCAL_C_INCLUDES += \
	external/wolfssl/wolfssl \
	external/wolfssl \

LOCAL_SRC_FILES:= \
	./src/crl.c \
	./src/internal.c \
	./src/keys.c \
	./src/ocsp.c \
	./src/sniffer.c \
	./src/ssl.c \
	./src/tls.c \
	./src/tls13.c \
	./src/wolfio.c

LOCAL_SRC_FILES+= \
	./wolfcrypt/src/aes.c \
	./wolfcrypt/src/arc4.c \
	./wolfcrypt/src/asm.c \
	./wolfcrypt/src/asn.c \
	./wolfcrypt/src/blake2b.c \
	./wolfcrypt/src/blake2s.c \
	./wolfcrypt/src/camellia.c \
	./wolfcrypt/src/chacha.c \
	./wolfcrypt/src/chacha20_poly1305.c \
	./wolfcrypt/src/cmac.c \
	./wolfcrypt/src/coding.c \
	./wolfcrypt/src/compress.c \
	./wolfcrypt/src/cpuid.c \
	./wolfcrypt/src/cryptocb.c \
	./wolfcrypt/src/curve25519.c \
	./wolfcrypt/src/des3.c \
	./wolfcrypt/src/dh.c \
	./wolfcrypt/src/dsa.c \
	./wolfcrypt/src/ecc.c \
	./wolfcrypt/src/ecc_fp.c \
	./wolfcrypt/src/ed25519.c \
	./wolfcrypt/src/error.c \
	./wolfcrypt/src/fe_low_mem.c \
	./wolfcrypt/src/fe_operations.c \
	./wolfcrypt/src/ge_low_mem.c \
	./wolfcrypt/src/ge_operations.c \
	./wolfcrypt/src/hash.c \
	./wolfcrypt/src/hc128.c \
	./wolfcrypt/src/hmac.c \
	./wolfcrypt/src/idea.c \
	./wolfcrypt/src/integer.c \
	./wolfcrypt/src/logging.c \
	./wolfcrypt/src/md2.c \
	./wolfcrypt/src/md4.c \
	./wolfcrypt/src/md5.c \
	./wolfcrypt/src/memory.c \
	./wolfcrypt/src/pkcs12.c \
	./wolfcrypt/src/pkcs7.c \
	./wolfcrypt/src/poly1305.c \
	./wolfcrypt/src/pwdbased.c \
	./wolfcrypt/src/rabbit.c \
	./wolfcrypt/src/random.c \
	./wolfcrypt/src/ripemd.c \
	./wolfcrypt/src/rsa.c \
	./wolfcrypt/src/selftest.c \
	./wolfcrypt/src/sha.c \
	./wolfcrypt/src/sha256.c \
	./wolfcrypt/src/sha3.c \
	./wolfcrypt/src/sha512.c \
	./wolfcrypt/src/signature.c \
	./wolfcrypt/src/sp_arm32.c \
	./wolfcrypt/src/sp_arm64.c \
	./wolfcrypt/src/sp_armthumb.c \
	./wolfcrypt/src/sp_c32.c \
	./wolfcrypt/src/sp_c64.c \
	./wolfcrypt/src/sp_cortexm.c \
	./wolfcrypt/src/sp_int.c \
	./wolfcrypt/src/sp_x86_64.c \
	./wolfcrypt/src/srp.c \
	./wolfcrypt/src/tfm.c \
	./wolfcrypt/src/wc_encrypt.c \
	./wolfcrypt/src/wc_pkcs11.c \
	./wolfcrypt/src/wc_port.c \
	./wolfcrypt/src/wolfevent.c \
	./wolfcrypt/src/wolfmath.c

include $(BUILD_SHARED_LIBRARY)

