#include <efi.h>
#include <efilib.h>
#include <Library/BaseCryptLib.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "shim.h"
#include "keygen.h"

static UINT8 seed[SHA512_DIGEST_LENGTH];

static EFI_STATUS get_variable (CHAR16 *name, EFI_GUID guid, UINT32 *attributes,
				UINTN *size, void **buffer)
{
	EFI_STATUS efi_status;
	char allocate = !(*size);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, name, &guid,
				       attributes, size, buffer);

	if (efi_status != EFI_BUFFER_TOO_SMALL || !allocate) {
		return efi_status;
	}

	*buffer = AllocatePool(*size);

	if (!*buffer) {
		Print(L"Unable to allocate variable buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, name, &guid,
				       attributes, size, *buffer);

	return efi_status;
}

static EFI_STATUS sha512sum (void *Data, UINTN DataSize, UINT8 *hash)
{
	EFI_STATUS status;
	SHA512_CTX ctx;

	if (!SHA512_Init(&ctx)) {
		Print(L"Unable to initialise hash");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	if (Data && DataSize) {
		if (!(SHA512_Update(&ctx, Data, DataSize))) {
			Print(L"Unable to generate hash");
			status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
	}

	if (!(SHA512_Final(hash, &ctx))) {
		Print(L"Unable to finalise hash");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	status = EFI_SUCCESS;
done:
	return status;
}

static __inline__ unsigned rdtsc (void)
{
	unsigned hi, lo;

	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));

	return lo;
}

void collect_entropy (void)
{
	unsigned count, shift;

	count = rdtsc();
	shift = rdtsc() % (SHA512_DIGEST_LENGTH - sizeof(unsigned));

	CopyMem(seed+shift, &count, sizeof(unsigned));
	sha512sum(seed, SHA512_DIGEST_LENGTH, seed);

	RandomSeed(seed, sizeof(seed));
}

static __inline__ void cpuid (unsigned info, unsigned *eax, unsigned *ebx,
			      unsigned *ecx, unsigned *edx)
{
	__asm__("xchg %%ebx, %%edi;"
		"cpuid;"
		"xchg %%ebx, %%edi;"
		:"=a" (*eax), "=D" (*ebx), "=c" (*ecx), "=d" (*edx)
		:"0" (info));
}

static BOOLEAN rdrand_support ()
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	if ((ecx & 0x40000000) == 0x40000000)
		return TRUE;
	return FALSE;
}

static __inline__ int rdrand64_step (UINT64 *therand)
{
	unsigned char err;

	__asm__ __volatile__("rdrand %0 ; setc %1"
			     : "=r" (*therand), "=qm" (err));

	return (int)err;
}

static void rdrand_seed (void)
{
	UINT8 hw_seed[SHA512_DIGEST_LENGTH];
	UINT64 therand;
	int i;

	for (i = 0; i < (SHA512_DIGEST_LENGTH / sizeof(UINT64)); i++) {
		rdrand64_step(&therand);
		CopyMem((hw_seed + i*sizeof(UINT64)), &therand, sizeof(UINT64));
	}

	RandomSeed(hw_seed, sizeof(hw_seed));
}

static EFI_STATUS time_base_seed (void)
{
	EFI_TIME time;
	EFI_STATUS efi_status;
	UINT32 shift, mod;

	efi_status = uefi_call_wrapper(RT->GetTime, 2, &time, NULL);
	if (efi_status != EFI_SUCCESS)
		return efi_status;

	mod = sizeof(seed) - sizeof(EFI_TIME);
	shift = rdtsc() % mod;

	CopyMem((void *)seed+shift, (void *)&time, sizeof(EFI_TIME));

	efi_status = sha512sum(seed, SHA512_DIGEST_LENGTH, seed);
	if (efi_status != EFI_SUCCESS)
		return efi_status;

	if (!RandomSeed(seed, sizeof(seed)))
		return EFI_ABORTED;

	return EFI_SUCCESS;
}

EFI_STATUS setup_rand (void)
{
	if (rdrand_support())
		rdrand_seed();

	return time_base_seed();
}

static ASN1_INTEGER *generate_serial (void)
{
	ASN1_INTEGER *serial = NULL;
	BIGNUM *b;

	b = BN_new ();

	if (b == NULL)
		return NULL;

	if (!BN_pseudo_rand(b, 64, 0, 0))
		goto error;

	serial = BN_to_ASN1_INTEGER(b, serial);
	if (!serial) {
		goto error;
	}

error:
	BN_free(b);

	return serial;
}

static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

/*
 * Generate a X509 certificate from the given RSA key
 */
static int generate_X509 (RSA *rsa, const int days, void **output)
{
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	ASN1_INTEGER *serial = NULL;
	X509_NAME *name;
	int length = -1;

	if (rsa == NULL)
		return -1;

	cert = X509_new ();
	if (!cert) {
		return -1;
	}

	pkey = EVP_PKEY_new ();
	if (!pkey) {
		goto error;
	}

	if (!EVP_PKEY_assign_RSA (pkey, rsa)) {
		goto error;
	}

	X509_set_pubkey (cert, pkey);

	serial = generate_serial ();
	if (!serial) {
		goto error;
	}

	X509_set_serialNumber (cert, serial);
	X509_gmtime_adj (X509_get_notBefore(cert), 0);
	X509_gmtime_adj (X509_get_notAfter(cert), (long)60*60*24*days);

	name = X509_get_subject_name (cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (unsigned char *)"Temp key", -1, -1, 0);
	if (!X509_set_issuer_name(cert, name)) {
		goto error;
	}

	add_ext(cert, NID_basic_constraints, "critical,CA:FALSE");
	add_ext(cert, NID_key_usage, "critical,digitalSignature");
	add_ext(cert, NID_subject_key_identifier, "hash");
	add_ext(cert, NID_authority_key_identifier, "keyid:always");

	if (!X509_sign (cert, pkey, EVP_sha256())) {
		goto error;
	}

	length = i2d_X509(cert, (unsigned char **)output);
	if (length <= 0) {
		*output = NULL;
		goto error;
	}

error:
	if (cert)
		X509_free (cert);

	if (pkey)
		EVP_PKEY_free (pkey);

	if (serial)
		ASN1_INTEGER_free (serial);

	return length;
}

/*
 * Generate a PKCS#8 key from the given RSA key
 */
static BUF_MEM *generate_pkcs8 (RSA *rsa)
{
	PKCS8_PRIV_KEY_INFO *pk8inf = NULL;
	BIO *pkcs8_bio = NULL;
	EVP_PKEY *pkey = NULL;
	BUF_MEM *bptr = NULL;

	if (rsa == NULL)
		return NULL;

	pkey = EVP_PKEY_new ();
	if (!pkey) {
		goto error;
	}

	if (!EVP_PKEY_assign_RSA (pkey, rsa)) {
		goto error;
	}

	pk8inf = EVP_PKEY2PKCS8_broken(pkey, PKCS8_OK);
	if (!pk8inf) {
		goto error;
	}

	pkcs8_bio = BIO_new (BIO_s_mem());
	i2d_PKCS8_PRIV_KEY_INFO_bio(pkcs8_bio, pk8inf);

error:
	if (pk8inf)
		PKCS8_PRIV_KEY_INFO_free (pk8inf);

	if (pkcs8_bio) {
		BIO_get_mem_ptr (pkcs8_bio, &bptr);
		BIO_set_close (pkcs8_bio, BIO_NOCLOSE);
		BIO_free (pkcs8_bio);
	}

	return bptr;
}

EFI_STATUS generate_new_keys (const int bits, const int days)
{
	EFI_GUID hibernate_var = EFI_HIBERNATE_GUID;
	EFI_STATUS status;
	RSA *Rsa = NULL, *Rsa_priv = NULL;
	void *der_cert = NULL;
	int length;
	BUF_MEM *pkcs8;

	Rsa = RsaNew();
	if (!Rsa) {
		return EFI_OUT_OF_RESOURCES;
	}

	if (!RsaGenerateKey(Rsa, bits, NULL, 0)) {
		return EFI_ABORTED;
	}

	Rsa_priv = RSAPrivateKey_dup (Rsa);

	status = EFI_ABORTED;

	length = generate_X509 (Rsa, days, &der_cert);
	if (length <= 0) {
		Print(L"Failed to generate X509 certificate\n");
		goto error;
	}

	pkcs8 = generate_pkcs8 (Rsa_priv);
	if (pkcs8 == NULL) {
		Print(L"Failed to generate PKCS8\n");
		goto error;
	}

	status = uefi_call_wrapper(RT->SetVariable, 5, L"NextWakeKey",
				   &hibernate_var,
				   EFI_VARIABLE_NON_VOLATILE |
				   EFI_VARIABLE_BOOTSERVICE_ACCESS,
				   length, der_cert);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to write NextWakeKey\n");
		goto error;
	}

	status = uefi_call_wrapper(RT->SetVariable, 5, L"S4SignKey",
				   &hibernate_var,
				   EFI_VARIABLE_NON_VOLATILE |
				   EFI_VARIABLE_BOOTSERVICE_ACCESS |
				   EFI_VARIABLE_RUNTIME_ACCESS,
				   pkcs8->length, pkcs8->data);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to write S4SignKey\n");
		goto error;
	}

error:
	if (der_cert)
		FreePool (der_cert);

	if (pkcs8)
		BUF_MEM_free (pkcs8);

	return status;
}

EFI_STATUS copy_certs (void)
{
	EFI_GUID hibernate_var = EFI_HIBERNATE_GUID;
	EFI_STATUS status;
	UINTN len = 0;
	UINT8 *Data = NULL;
	UINT32 attr;

	status = get_variable(L"NextWakeKey", hibernate_var, &attr,
			      &len, (void **)&Data);
	if (status != EFI_SUCCESS) {
		goto error;
	} else if (attr & EFI_VARIABLE_RUNTIME_ACCESS) {
		Print(L"NextWakeKey is compromised!\nErase the key\n");
		if (LibDeleteVariable(L"NextWakeKey", &hibernate_var) != EFI_SUCCESS) {
			Print(L"Failed to erase NextWakeKey\n");
		}
		status = EFI_ABORTED;
		goto error;
	}

	status = uefi_call_wrapper(RT->SetVariable, 5,
				   L"S4WakeKey",
				   &hibernate_var,
				   EFI_VARIABLE_BOOTSERVICE_ACCESS |
				   EFI_VARIABLE_RUNTIME_ACCESS,
				   len, Data);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to write S4WakeKey\n");
		goto error;
	}

error:
	if (Data)
		FreePool(Data);

	return status;
}
