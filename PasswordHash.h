#ifndef __PASSWORD_HASH_H__
#define __PASSWORD_HASH_H__

#define PASSWORD_HASH_SIZE 88

enum HashMethod {
	Tranditional_DES = 0,
	Extend_BSDI_DES,
	MD5_BASED,
	SHA256_BASED,
	SHA512_BASED,
	BLOWFISH_BASED
};

typedef struct {
	UINT16 method;
	UINT32 iter_count;
	UINT16 salt_size;
	UINT8  salt[16];
	UINT8  hash[64];
} __attribute__ ((packed)) PASSWORD_HASH;

#endif /* __PASSWORD_HASH_H__ */
