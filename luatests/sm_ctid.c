/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <lua.h>
#include <lauxlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/hex.h>

size_t hex_string_to_bytes(const char *hexstring, uint8_t *out, size_t maxbytes)
{
	size_t hexsz = strlen(hexstring);
	if (hexsz > maxbytes * 2)
		hexsz = maxbytes * 2;
	size_t outlen = 0;
	hex_to_bytes(hexstring, hexsz, out, &outlen);
	return outlen;
}

void bytes_to_hex_string(const uint8_t *bytes, size_t length, char *str)
{
	for (size_t i = 0; i < length; ++i)
	{
		sprintf(str + i * 2, "%02X", bytes[i]);
	}
	str[length * 2] = '\0';
}

int get_public_key_from_der(SM2_KEY *key, const char *pub_der, size_t publen)
{
	uint8_t pub_buf[512];
	publen = hex_string_to_bytes(pub_der, pub_buf, 512);
	const uint8_t *pub_ptr = pub_buf;
	format_bytes(stderr, 0, 4, "public key der", pub_buf, publen);
	if (sm2_public_key_info_from_der(key, &pub_ptr, &publen) != 1 || asn1_length_is_zero(publen) != 1)
	{
		return 0;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", key);
	return 1;
}

int get_private_key_from_der(SM2_KEY *key, const char *pri_der, size_t prilen)
{
	uint8_t pri_buf[512];
	prilen = hex_string_to_bytes(pri_der, pri_buf, 512);
	const uint8_t *attrs;
	size_t attrs_len;
	const uint8_t *pri_ptr = pri_buf;
	format_bytes(stderr, 0, 4, "private key der", pri_buf, prilen);
	if (sm2_private_key_info_from_der(key, &attrs, &attrs_len, &pri_ptr, &prilen) != 1 || asn1_length_is_zero(prilen) != 1)
	{
		return 0;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", key);
	return 1;
}

void public_key_to_hex(SM2_KEY *key, char *hex)
{
	uint8_t pub_bytes[64];
	sm2_z256_point_to_bytes(&key->public_key, pub_bytes);
	// 以04开头
	hex[0] = '0';
	hex[1] = '4';
	bytes_to_hex_string(pub_bytes, 64, hex + 2);
}

void private_key_to_hex(SM2_KEY *key, char *hex)
{
	uint8_t pri_bytes[32];
	sm2_z256_to_bytes(key->private_key, pri_bytes);
	bytes_to_hex_string(pri_bytes, 32, hex);
}

int set_pulick_key_from_hex(SM2_KEY *key, const char *hex)
{
	if (strlen(hex) != 130)
	{
		fprintf(stderr, "public key error\n");
		return 0;
	}
	uint8_t tag = 0;
	hex_string_to_bytes(hex, &tag, 1);
	if (tag != 0x04)
	{
		fprintf(stderr, "public key not start with 04\n");
		return 0;
	}

	uint8_t pub_buf[64];
	hex_string_to_bytes(hex + 2, pub_buf, 64);
	if (sm2_z256_point_from_bytes(&key->public_key, pub_buf) < 0)
	{
		fprintf(stderr, "set public error\n");
		return 0;
	}
	return 1;
}

int set_private_key_from_hex(SM2_KEY *key, const char *hex)
{
	if (strlen(hex) != 64)
	{
		fprintf(stderr, "private key error\n");
		return 0;
	}

	uint8_t pri_buf[32];
	hex_string_to_bytes(hex, pri_buf, 32);
	sm2_z256_from_bytes(key->private_key, pri_buf);
	return 1;
}

int to_hex_C1C3C2(SM2_CIPHERTEXT *C, const uint8_t *in, size_t inlen, char *enctext)
{
	if (sm2_ciphertext_from_der(C, &in, &inlen) != 1 || asn1_length_is_zero(inlen) != 1)
	{
		fprintf(stderr, "to ciphertext failure\n");
		return 0;
	}

	size_t encsz = 32 + 32 + 32 + SM2_MAX_PLAINTEXT_SIZE;
	uint8_t encbuf[encsz];
	memcpy(encbuf, C->point.x, 32);
	memcpy(encbuf + 32, C->point.y, 32);
	memcpy(encbuf + 32 + 32, C->hash, 32);
	memcpy(encbuf + 32 + 32 + 32, C->ciphertext, (size_t)C->ciphertext);

	// char enctext[encsz+2+2];
	// 以04开头
	enctext[0] = '0';
	enctext[1] = '4';
	bytes_to_hex_string(encbuf, encsz, enctext);
	return 1;
}

int sm2keygen(lua_State *L)
{
	SM2_KEY key;
	if (sm2_key_generate(&key) != 1)
	{
		fprintf(stderr, "sm2 keygen failure\n");
		return 0;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	// 私钥转成16进制字符串
	char pri_hex[32 * 2 + 2];
	private_key_to_hex(&key, pri_hex);

	// 公钥转成16进制字符串
	char pub_hex[64 * 2 + 2 + 2];
	public_key_to_hex(&key, pub_hex);

	lua_pushlstring(L, pub_hex, strlen(pub_hex));
	lua_pushlstring(L, pri_hex, strlen(pri_hex));
	return 2;
}

int sm2encrypt(lua_State *L)
{
	size_t inlen = 0;
	const char *indata = luaL_checklstring(L, 1, &inlen);
	if (inlen > SM2_MAX_PLAINTEXT_SIZE)
	{
		fprintf(stderr, "sm2 encrypt: input long than SM2_MAX_PLAINTEXT_SIZE (%d)\n", SM2_MAX_PLAINTEXT_SIZE);
		return 0;
	}
	uint8_t inbuf[SM2_MAX_PLAINTEXT_SIZE];
	memcpy(inbuf, indata, inlen);

	SM2_KEY key;
	// 公钥(十六进制字符串)以04开头
	size_t pubsz = 0;
	const char *pub_hex = luaL_checklstring(L, 2, &pubsz);
	if (set_pulick_key_from_hex(&key, pub_hex) != 1)
	{
		return 0;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	// 加密
	SM2_ENC_CTX ctx;
	if (sm2_encrypt_init(&ctx) != 1)
	{
		fprintf(stderr, "sm2 encrypt: sm2_encrypt_init failed\n");
		return 0;
	}
	if (sm2_encrypt_update(&ctx, inbuf, inlen) != 1)
	{
		fprintf(stderr, "sm2 encrypt: sm2_encrypt_update failed\n");
		return 0;
	}
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t outlen = sizeof(outbuf);
	if (sm2_encrypt_finish(&ctx, &key, outbuf, &outlen) != 1)
	{
		fprintf(stderr, "sm2 encrypt: sm2_encrypt_finish error\n");
		return 0;
	}
	printf("encrypted cipher size=%ld\n", outlen);

	/*
	//转换成hex C1C3C2
	size_t encsz = 32 + 32 + 32 + SM2_MAX_PLAINTEXT_SIZE;
	char enctext[encsz * 2 + 2 + 2];
	SM2_CIPHERTEXT C;
	to_hex_C1C3C2(&C, outbuf, outlen, enctext);
	*/

	lua_pushlstring(L, (const char *)outbuf, outlen);
	return 1;
}

int sm2decrypt(lua_State *L)
{
	uint8_t inbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t inlen = 0;
	const char *indata = luaL_checklstring(L, 1, &inlen);
	if (inlen > SM2_MAX_CIPHERTEXT_SIZE)
	{
		fprintf(stderr, "sm2 decrypt: input long than SM2_MAX_CIPHERTEXT_SIZE (%d)\n", SM2_MAX_CIPHERTEXT_SIZE);
		return 0;
	}
	memcpy(inbuf, indata, inlen);

	SM2_KEY key;

	// 私钥(十六进制字符串)
	size_t prisz = 0;
	const char *pri_hex = luaL_checklstring(L, 2, &prisz);
	if (set_private_key_from_hex(&key, pri_hex) != 1)
	{
		return 0;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	// 解密
	SM2_DEC_CTX ctx;
	uint8_t outbuf[SM2_MAX_PLAINTEXT_SIZE];
	size_t outlen = 0;
	if (sm2_decrypt_init(&ctx) != 1)
	{
		fprintf(stderr, "sm2 decrypt: sm2_decrypt_init failed\n");
		return 0;
	}
	if (sm2_decrypt_update(&ctx, inbuf, inlen) != 1)
	{
		fprintf(stderr, "sm2 decrypt: sm2_decyrpt_update failed\n");
		return 0;
	}
	if (sm2_decrypt_finish(&ctx, &key, outbuf, &outlen) != 1)
	{
		fprintf(stderr, "sm2 decrypt: decryption failure\n");
		return 0;
	}

	lua_pushlstring(L, (const char *)outbuf, outlen);
	return 1;
}
// 密文是以十六进制字符串形式存在，并遵循C1C3C2格式,以标记04开头
int sm2decrypt_hex_C1C3C2(lua_State *L)
{
	SM2_KEY key;
	uint8_t outbuf[SM2_MAX_PLAINTEXT_SIZE];
	size_t outlen = 0;

	size_t sz = 0;
	const char *encrypttext = luaL_checklstring(L, 1, &sz);
	uint8_t tag = 0;
	hex_string_to_bytes(encrypttext, &tag, 1);
	if (tag != 0x04)
	{
		fprintf(stderr, "sm2 decrypt C1C3C2: encrypt text not start with 04\n");
		return 0;
	}

	// 分解密文
	uint8_t C1X[32];
	uint8_t C1Y[32];
	uint8_t hash[32];
	uint8_t ctext[SM2_MAX_PLAINTEXT_SIZE];
	size_t size = SM2_MAX_PLAINTEXT_SIZE;

	hex_string_to_bytes(encrypttext + 1 * 2, C1X, 32);
	hex_string_to_bytes(encrypttext + 1 * 2 + 32 * 2, C1Y, 32);
	hex_string_to_bytes(encrypttext + 1 * 2 + 32 * 2 + 32 * 2, hash, 32);
	size = hex_string_to_bytes(encrypttext + 1 * 2 + 32 * 2 + 32 * 2 + 32 * 2, ctext, SM2_MAX_PLAINTEXT_SIZE);
	if (size > SM2_MAX_CIPHERTEXT_SIZE)
	{
		fprintf(stderr, "sm2 decrypt C1C3C2: ciphertext long than SM2_MAX_CIPHERTEXT_SIZE (%d)\n", SM2_MAX_CIPHERTEXT_SIZE);
		return 0;
	}
	SM2_CIPHERTEXT ciphertext;
	memcpy(ciphertext.point.x, C1X, 32);
	memcpy(ciphertext.point.y, C1Y, 32);
	memcpy(ciphertext.hash, hash, 32);
	memcpy(ciphertext.ciphertext, ctext, size);
	ciphertext.ciphertext_size = size;

	/*
	   // print ciphertext
	   SM2_CIPHERTEXT *c = &ciphertext;
	   format_print(stderr, 0, 4, "%s\n", "ciphertext");
	   format_bytes(stderr, 0, 8, "XCoordinate", c->point.x, 32);
	   format_bytes(stderr, 0, 8, "YCoordinate", c->point.y, 32);
	   format_bytes(stderr, 0, 8, "HASH", c->hash, 32);
	   format_bytes(stderr, 0, 8, "CipherText", c->ciphertext, c->ciphertext_size);
	*/

	// 私钥(十六进制字符串)
	size_t prisz = 0;
	const char *pri_hex = luaL_checklstring(L, 2, &prisz);
	if (set_private_key_from_hex(&key, pri_hex) != 1)
	{
		return 0;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	if (sm2_do_decrypt(&key, &ciphertext, outbuf, &outlen) != 1)
	{
		fprintf(stderr, "sm2 decrypt C1C3C2: decryption failure\n");
		return 0;
	}

	format_bytes(stderr, 0, 4, "plaintext", outbuf, outlen);
	lua_pushlstring(L, (const char *)outbuf, outlen);
	return 1;
}

int sm3digest(lua_State *L)
{
	SM3_DIGEST_CTX sm3_ctx;
	uint8_t dgst[32];

	size_t inlen = 0;
	const char *indata = luaL_checklstring(L, 1, &inlen);
	if (inlen <= 0)
	{
		fprintf(stderr, "sm3 digest: indata is empty\n");
		return 0;
	}

	if (sm3_digest_init(&sm3_ctx, NULL, 0) != 1)
	{
		fprintf(stderr, "sm3 digest: init error\n");
		return 0;
	}

	if (sm3_digest_update(&sm3_ctx, (uint8_t *)indata, inlen) != 1)
	{
		fprintf(stderr, "sm3 digest: inner error\n");
		return 0;
	}

	if (sm3_digest_finish(&sm3_ctx, dgst) != 1)
	{
		fprintf(stderr, "sm3 digest: inner error\n");
		return 0;
	}
	memset(&sm3_ctx, 0, sizeof(sm3_ctx));
	lua_pushlstring(L, (const char *)dgst, sizeof(dgst));
	return 1;
}

int sm2sign(lua_State *L)
{
	char *id = SM2_DEFAULT_ID;
	size_t inlen = 0;
	const char *indata = luaL_checklstring(L, 1, &inlen);
	format_bytes(stderr, 0, 4, "indata", (const uint8_t *)indata, inlen);

	SM2_KEY key;
	// 公钥(十六进制字符串)以04开头
	size_t pubsz = 0;
	const char *pub_hex = luaL_checklstring(L, 2, &pubsz);
	if (set_pulick_key_from_hex(&key, pub_hex) != 1)
		return 0;

	// 私钥(十六进制字符串)
	size_t prisz = 0;
	const char *pri_hex = luaL_checklstring(L, 3, &prisz);
	if (set_private_key_from_hex(&key, pri_hex) != 1)
		return 0;
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	SM2_SIGN_CTX sign_ctx;
	if (sm2_sign_init(&sign_ctx, &key, id, strlen(id)) != 1)
	{
		fprintf(stderr, "sm2 sign: init error\n");
		return 0;
	}
	if (sm2_sign_update(&sign_ctx, (uint8_t *)indata, inlen) != 1)
	{
		fprintf(stderr, "sm2 sign: update error\n");
		return 0;
	}
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	if (sm2_sign_finish(&sign_ctx, sig, &siglen) != 1)
	{
		fprintf(stderr, "sm2 sign: finish error\n");
		return 0;
	}
	format_bytes(stderr, 0, 4, "sign", sig, siglen);

	lua_pushlstring(L, (const char *)sig, siglen);
	return 1;
}

int sm2verify(lua_State *L)
{
	char *id = SM2_DEFAULT_ID;
	size_t inlen = 0;
	const char *indata = luaL_checklstring(L, 1, &inlen);
	format_bytes(stderr, 0, 4, "indata", (const uint8_t *)indata, inlen);

	// 签名凭据(十六进制字符串)
	size_t siglen = 0;
	const char *sig_der = luaL_checklstring(L, 2, &siglen);
	if (siglen > SM2_MAX_SIGNATURE_SIZE * 2)
	{
		fprintf(stderr, "signature too longer\n");
		return 0;
	}
	uint8_t sig_buf[SM2_MAX_SIGNATURE_SIZE];
	siglen = hex_string_to_bytes(sig_der, sig_buf, SM2_MAX_SIGNATURE_SIZE);
	format_bytes(stderr, 0, 4, "signature", sig_buf, siglen);

	SM2_KEY key;
	// 公钥(十六进制字符串)以04开头
	size_t pubsz = 0;
	const char *pub_hex = luaL_checklstring(L, 3, &pubsz);
	if (set_pulick_key_from_hex(&key, pub_hex) != 1)
		return 0;
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	// 验签
	SM2_VERIFY_CTX verify_ctx;
	if (sm2_verify_init(&verify_ctx, &key, id, strlen(id)) != 1)
	{
		fprintf(stderr, "sm2 verify: init error\n");
		return 0;
	}
	if (sm2_verify_update(&verify_ctx, (uint8_t *)indata, inlen) != 1)
	{
		fprintf(stderr, "sm2 verify: update error\n");
		return 0;
	}
	int vr = 0;
	if ((vr = sm2_verify_finish(&verify_ctx, sig_buf, siglen)) < 0)
	{
		fprintf(stderr, "sm2 verify: finish error\n");
		return 0;
	}

	fprintf(stdout, "verify : %s\n", vr == 1 ? "success" : "failure");
	lua_pushboolean(L, vr);
	return 1;
}

int sm2key_to_der(lua_State *L)
{
	SM2_KEY key;
	// 公钥(十六进制字符串)以04开头
	size_t pubsz = 0;
	const char *pub_hex = luaL_checklstring(L, 1, &pubsz);
	if (set_pulick_key_from_hex(&key, pub_hex) != 1)
	{
		return 0;
	}

	// 私钥(十六进制字符串)
	size_t prisz = 0;
	const char *pri_hex = luaL_checklstring(L, 2, &prisz);
	if (set_private_key_from_hex(&key, pri_hex) != 1)
	{
		return 0;
	}

	sm2_key_print(stderr, 0, 4, "SM2_KEY", &key);

	// 生成der格式的公钥
	uint8_t pub_buff[128];
	uint8_t *pub_ptr = pub_buff;
	size_t pub_len = 0;
	if (sm2_public_key_info_to_der(&key, &pub_ptr, &pub_len) != 1)
	{
		fprintf(stderr, "public key to der failure\n");
		return 0;
	}
	format_bytes(stderr, 0, 4, "DER public key\n", pub_buff, pub_len);

	// DER格式公钥转成16进制字符串
	char pub_der[pub_len * 2 + 2];
	bytes_to_hex_string(pub_buff, pub_len, pub_der);

	// 生成der格式的私钥
	uint8_t pri_buff[512];
	uint8_t *pri_ptr = pri_buff;
	size_t pri_len = 0;
	if (sm2_private_key_info_to_der(&key, &pri_ptr, &pri_len) != 1)
	{
		fprintf(stderr, "private key to der failure\n");
		return 0;
	}
	format_bytes(stderr, 0, 4, "DER private key", pri_buff, pri_len);

	// der格式私钥转成16进制字符串
	char pri_der[pri_len * 2 + 2];
	bytes_to_hex_string(pri_buff, pri_len, pri_der);

	lua_pushlstring(L, pub_der, strlen(pub_der));
	lua_pushlstring(L, pri_der, strlen(pri_der));
	return 2;
}

LUAMOD_API int luaopen_ctid(lua_State *L)
{
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{"keygen", sm2keygen},
		{"encrypt", sm2encrypt},
		{"decrypt", sm2decrypt},
		{"decrypt_C1C3C2", sm2decrypt_hex_C1C3C2},
		{"sm3digest", sm3digest},
		{"sign", sm2sign},
		{"verify", sm2verify},
		{"key_to_der", sm2key_to_der},
		{NULL, NULL},
	};
	luaL_newlib(L, l);
	return 1;
}