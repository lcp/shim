/*
 * shim - trivial UEFI first-stage bootloader
 *
 * Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Significant portions of this code are derived from Tianocore
 * (http://tianocore.sf.net) and are Copyright 2009-2012 Intel
 * Corporation.
 */

#include <efi.h>
#include <efilib.h>
#include <Library/BaseCryptLib.h>
#include <openssl/x509.h>
#include "PeImage.h"
#include "shim.h"
#include "signature.h"

#define SECOND_STAGE L"\\grub.efi"

static EFI_SYSTEM_TABLE *systab;
static EFI_STATUS (EFIAPI *entry_point) (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);

/*
 * The vendor certificate used for validating the second stage loader
 */

#include "cert.h"

#define EFI_IMAGE_SECURITY_DATABASE_GUID { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }}

typedef enum {
	DATA_FOUND,
	DATA_NOT_FOUND,
	VAR_NOT_FOUND
} CHECK_STATUS;

typedef struct {
	UINT32 MokSize;
	UINT8 *Mok;
} MokListNode;

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

	if (allocate)
		*buffer = AllocatePool(*size);

	if (!*buffer) {
		Print(L"Unable to allocate variable buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, name, &guid,
				       attributes, size, *buffer);

	return efi_status;
}

static EFI_STATUS delete_variable (CHAR16 *name, EFI_GUID guid)
{
	EFI_STATUS efi_status;

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, name, &guid,
				       0, 0, (UINT8 *)NULL);

	return efi_status;
}

static EFI_INPUT_KEY get_keystroke (void)
{
	EFI_INPUT_KEY key;
	UINTN EventIndex;

	uefi_call_wrapper(BS->WaitForEvent, 3, 1, &ST->ConIn->WaitForKey,
			  &EventIndex);
	uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &key);

	return key;
}

static EFI_STATUS get_sha256sum (void *Data, int DataSize, UINT8 *hash)
{
	EFI_STATUS status;
	unsigned int ctxsize;
	void *ctx = NULL;

	ctxsize = Sha256GetContextSize();
	ctx = AllocatePool(ctxsize);

	if (!ctx) {
		Print(L"Unable to allocate memory for hash context\n");
		return EFI_OUT_OF_RESOURCES;
	}

	if (!Sha256Init(ctx)) {
		Print(L"Unable to initialise hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	if (!(Sha256Update(ctx, Data, DataSize))) {
		Print(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	if (!(Sha256Final(ctx, hash))) {
		Print(L"Unable to finalise hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	status = EFI_SUCCESS;
done:
	return status;
}

static MokListNode *build_mok_list(UINT32 num, void *Data, UINTN DataSize) {
	MokListNode *list;
	int i, remain = DataSize;
	void *ptr;

	list = AllocatePool(sizeof(MokListNode) * num);

	if (!list) {
		Print(L"Unable to allocate MOK list\n");
		return NULL;
	}

	ptr = Data;
	for (i = 0; i < num; i++) {
		if (remain < 0) {
			Print(L"MOK list was corrupted\n");
			FreePool(list);
			return NULL;
		}

		CopyMem(&list[i].MokSize, ptr, sizeof(UINT32));
		ptr += sizeof(UINT32);
		list[i].Mok = ptr;
		ptr += list[i].MokSize;

		remain -= sizeof(UINT32) + list[i].MokSize;
	}

	return list;
}

/*
 * Perform basic bounds checking of the intra-image pointers
 */
static void *ImageAddress (void *image, int size, unsigned int address)
{
	if (address > size)
		return NULL;

	return image + address;
}

/*
 * Perform the actual relocation
 */
static EFI_STATUS relocate_coff (PE_COFF_LOADER_IMAGE_CONTEXT *context,
				 void *data)
{
	EFI_IMAGE_BASE_RELOCATION *RelocBase, *RelocBaseEnd;
	UINT64 Adjust;
	UINT16 *Reloc, *RelocEnd;
	char *Fixup, *FixupBase, *FixupData = NULL;
	UINT16 *Fixup16;
	UINT32 *Fixup32;
	UINT64 *Fixup64;
	int size = context->ImageSize;
	void *ImageEnd = (char *)data + size;

	context->PEHdr->Pe32Plus.OptionalHeader.ImageBase = (UINT64)data;

	if (context->NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		Print(L"Image has no relocation entry\n");
		return EFI_UNSUPPORTED;
	}

	RelocBase = ImageAddress(data, size, context->RelocDir->VirtualAddress);
	RelocBaseEnd = ImageAddress(data, size, context->RelocDir->VirtualAddress + context->RelocDir->Size - 1);

	if (!RelocBase || !RelocBaseEnd) {
		Print(L"Reloc table overflows binary\n");
		return EFI_UNSUPPORTED;
	}

	Adjust = (UINT64)data - context->ImageAddress;

	while (RelocBase < RelocBaseEnd) {
		Reloc = (UINT16 *) ((char *) RelocBase + sizeof (EFI_IMAGE_BASE_RELOCATION));
		RelocEnd = (UINT16 *) ((char *) RelocBase + RelocBase->SizeOfBlock);

		if ((void *)RelocEnd < data || (void *)RelocEnd > ImageEnd) {
			Print(L"Reloc entry overflows binary\n");
			return EFI_UNSUPPORTED;
		}

		FixupBase = ImageAddress(data, size, RelocBase->VirtualAddress);
		if (!FixupBase) {
			Print(L"Invalid fixupbase\n");
			return EFI_UNSUPPORTED;
		}

		while (Reloc < RelocEnd) {
			Fixup = FixupBase + (*Reloc & 0xFFF);
			switch ((*Reloc) >> 12) {
			case EFI_IMAGE_REL_BASED_ABSOLUTE:
				break;

			case EFI_IMAGE_REL_BASED_HIGH:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16 = (UINT16) (*Fixup16 + ((UINT16) ((UINT32) Adjust >> 16)));
				if (FixupData != NULL) {
					*(UINT16 *) FixupData = *Fixup16;
					FixupData             = FixupData + sizeof (UINT16);
				}
				break;

			case EFI_IMAGE_REL_BASED_LOW:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16  = (UINT16) (*Fixup16 + (UINT16) Adjust);
				if (FixupData != NULL) {
					*(UINT16 *) FixupData = *Fixup16;
					FixupData             = FixupData + sizeof (UINT16);
				}
				break;

			case EFI_IMAGE_REL_BASED_HIGHLOW:
				Fixup32   = (UINT32 *) Fixup;
				*Fixup32  = *Fixup32 + (UINT32) Adjust;
				if (FixupData != NULL) {
					FixupData             = ALIGN_POINTER (FixupData, sizeof (UINT32));
					*(UINT32 *)FixupData  = *Fixup32;
					FixupData             = FixupData + sizeof (UINT32);
				}
				break;

			case EFI_IMAGE_REL_BASED_DIR64:
				Fixup64 = (UINT64 *) Fixup;
				*Fixup64 = *Fixup64 + (UINT64) Adjust;
				if (FixupData != NULL) {
					FixupData = ALIGN_POINTER (FixupData, sizeof(UINT64));
					*(UINT64 *)(FixupData) = *Fixup64;
					FixupData = FixupData + sizeof(UINT64);
				}
				break;

			default:
				Print(L"Unknown relocation\n");
				return EFI_UNSUPPORTED;
			}
			Reloc += 1;
		}
		RelocBase = (EFI_IMAGE_BASE_RELOCATION *) RelocEnd;
	}

	return EFI_SUCCESS;
}

static CHECK_STATUS check_db_cert(CHAR16 *dbname, WIN_CERTIFICATE_EFI_PKCS *data, UINT8 *hash)
{
	EFI_STATUS efi_status;
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert;
	UINT32 attributes;
	UINTN dbsize = 0;
	UINTN CertCount, Index;
	BOOLEAN IsFound = FALSE;
	void *db;
	EFI_GUID CertType = EfiCertX509Guid;

	efi_status = get_variable(dbname, secure_var, &attributes,
				  &dbsize, &db);

	if (efi_status != EFI_SUCCESS)
		return VAR_NOT_FOUND;

	CertList = db;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if (CompareGuid (&CertList->SignatureType, &CertType) == 0) {
			CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
			for (Index = 0; Index < CertCount; Index++) {
				IsFound = AuthenticodeVerify (data->CertData,
							      data->Hdr.dwLength - sizeof(data->Hdr),
							      Cert->SignatureData,
							      CertList->SignatureSize,
							      hash, SHA256_DIGEST_SIZE);
					}
			if (IsFound) {
				break;
			}

			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
		}

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	FreePool(db);

	if (IsFound)
		return DATA_FOUND;

	return DATA_NOT_FOUND;
}

static CHECK_STATUS check_db_hash(CHAR16 *dbname, UINT8 *data)
{
	EFI_STATUS efi_status;
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert;
	UINT32 attributes;
	UINTN dbsize = 0;
	UINTN CertCount, Index;
	BOOLEAN IsFound = FALSE;
	void *db;
	unsigned int SignatureSize = SHA256_DIGEST_SIZE;
	EFI_GUID CertType = EfiHashSha256Guid;

	efi_status = get_variable(dbname, secure_var, &attributes,
				  &dbsize, &db);

	if (efi_status != EFI_SUCCESS) {
		return VAR_NOT_FOUND;
	}

	CertList = db;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
		Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
		if (CompareGuid(&CertList->SignatureType, &CertType) == 0) {
			for (Index = 0; Index < CertCount; Index++) {
				if (CompareMem (Cert->SignatureData, data, SignatureSize) == 0) {
					//
					// Find the signature in database.
					//
					IsFound = TRUE;
					break;
				}

				Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
			}
			if (IsFound) {
				break;
			}
		}

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	FreePool(db);

	if (IsFound)
		return DATA_FOUND;

	return DATA_NOT_FOUND;
}

static EFI_STATUS check_blacklist (WIN_CERTIFICATE_EFI_PKCS *cert, UINT8 *hash)
{
	if (check_db_hash(L"dbx", hash) == DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_cert(L"dbx", cert, hash) == DATA_FOUND)
		return EFI_ACCESS_DENIED;

	return EFI_SUCCESS;
}

static EFI_STATUS check_whitelist (WIN_CERTIFICATE_EFI_PKCS *cert, UINT8 *hash)
{
	if (check_db_hash(L"db", hash) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_cert(L"db", cert, hash) == DATA_FOUND)
		return EFI_SUCCESS;

	return EFI_ACCESS_DENIED;
}

/*
 * Check whether we're in Secure Boot and user mode
 */

static BOOLEAN secure_mode (void)
{
	EFI_STATUS status;
	EFI_GUID global_var = EFI_GLOBAL_VARIABLE;
	UINTN charsize = sizeof(char);
	UINT8 sb, setupmode;
	UINT32 attributes;

	status = get_variable(L"SecureBoot", global_var, &attributes,
			      &charsize, (void *)&sb);

	/* FIXME - more paranoia here? */
	if (status != EFI_SUCCESS || sb != 1) {
		Print(L"Secure boot not enabled\n");
		return FALSE;
	}

	status = get_variable(L"SetupMode", global_var, &attributes,
			      &charsize, (void *)&setupmode);

	if (status == EFI_SUCCESS && setupmode == 1) {
		Print(L"Platform is in setup mode\n");
		return FALSE;
	}

	return TRUE;
}

/*
 * Check that the signature is valid and matches the binary
 */
static EFI_STATUS verify_buffer (char *data, int datasize,
			 PE_COFF_LOADER_IMAGE_CONTEXT *context, int whitelist)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	unsigned int size = datasize;
	unsigned int ctxsize;
	void *ctx = NULL;
	UINT8 hash[SHA256_DIGEST_SIZE];
	EFI_STATUS status = EFI_ACCESS_DENIED;
	char *hashbase;
	unsigned int hashsize;
	WIN_CERTIFICATE_EFI_PKCS *cert;
	unsigned int SumOfBytesHashed, SumOfSectionBytes;
	unsigned int index, pos;
	EFI_IMAGE_SECTION_HEADER  *Section;
	EFI_IMAGE_SECTION_HEADER  *SectionHeader = NULL;
	EFI_IMAGE_SECTION_HEADER  *SectionCache;
	unsigned int i;
	void *MokListData = NULL;
	UINTN MokListDataSize = 0;
	UINT32 MokNum;
	UINT32 attributes;
	MokListNode *list = NULL;

	cert = ImageAddress (data, size, context->SecDir->VirtualAddress);

	if (!cert) {
		Print(L"Certificate located outside the image\n");
		return EFI_INVALID_PARAMETER;
	}

	if (cert->Hdr.wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
		Print(L"Unsupported certificate type %x\n",
		      cert->Hdr.wCertificateType);
		return EFI_UNSUPPORTED;
	}

	/* FIXME: Check which kind of hash */

	ctxsize = Sha256GetContextSize();
	ctx = AllocatePool(ctxsize);

	if (!ctx) {
		Print(L"Unable to allocate memory for hash context\n");
		return EFI_OUT_OF_RESOURCES;
	}

	if (!Sha256Init(ctx)) {
		Print(L"Unable to initialise hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash start to checksum */
	hashbase = data;
	hashsize = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum -
		hashbase;

	if (!(Sha256Update(ctx, hashbase, hashsize))) {
		Print(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash post-checksum to start of certificate table */
	hashbase = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum +
		sizeof (int);
	hashsize = (char *)context->SecDir - hashbase;

	if (!(Sha256Update(ctx, hashbase, hashsize))) {
		Print(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash end of certificate table to end of image header */
	hashbase = (char *) &context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
	hashsize = context->PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders -
		(int) ((char *) (&context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1]) - data);

	if (!(Sha256Update(ctx, hashbase, hashsize))) {
		Print(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Sort sections */
	SumOfBytesHashed = context->PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;

	Section = (EFI_IMAGE_SECTION_HEADER *) (
		(char *)context->PEHdr + sizeof (UINT32) +
		sizeof (EFI_IMAGE_FILE_HEADER) +
		context->PEHdr->Pe32.FileHeader.SizeOfOptionalHeader
		);

	SectionCache = Section;

	for (index = 0, SumOfSectionBytes = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++, SectionCache++) {
		SumOfSectionBytes += SectionCache->SizeOfRawData;
	}

	if (SumOfSectionBytes >= datasize) {
		Print(L"Malformed binary: %x %x\n", SumOfSectionBytes, size);
		status = EFI_INVALID_PARAMETER;
		goto done;
	}

	SectionHeader = (EFI_IMAGE_SECTION_HEADER *) AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER) * context->PEHdr->Pe32.FileHeader.NumberOfSections);
	if (SectionHeader == NULL) {
		Print(L"Unable to allocate section header\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Sort the section headers */
	for (index = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++) {
		pos = index;
		while ((pos > 0) && (Section->PointerToRawData < SectionHeader[pos - 1].PointerToRawData)) {
			CopyMem (&SectionHeader[pos], &SectionHeader[pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		CopyMem (&SectionHeader[pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
		Section += 1;
	}

	/* Hash the sections */
	for (index = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++) {
		Section = &SectionHeader[index];
		if (Section->SizeOfRawData == 0) {
			continue;
		}
		hashbase  = ImageAddress(data, size, Section->PointerToRawData);
		hashsize  = (unsigned int) Section->SizeOfRawData;

		if (!hashbase) {
			Print(L"Malformed section header\n");
			return EFI_INVALID_PARAMETER;
		}

		if (!(Sha256Update(ctx, hashbase, hashsize))) {
			Print(L"Unable to generate hash\n");
			status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
		SumOfBytesHashed += Section->SizeOfRawData;
	}

	/* Hash all remaining data */
	if (size > SumOfBytesHashed) {
		hashbase = data + SumOfBytesHashed;
		hashsize = (unsigned int)(
			size -
			context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size -
			SumOfBytesHashed);

		if (!(Sha256Update(ctx, hashbase, hashsize))) {
			Print(L"Unable to generate hash\n");
			status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
	}

	if (!(Sha256Final(ctx, hash))) {
		Print(L"Unable to finalise hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	status = check_blacklist(cert, hash);

	if (status != EFI_SUCCESS) {
		Print(L"Binary is blacklisted\n");
		goto done;
	}

	if (whitelist) {
		status = check_whitelist(cert, hash);

		if (status == EFI_SUCCESS) {
			Print(L"Binary is whitelisted\n");
			goto done;
		}
	}

	if (AuthenticodeVerify(cert->CertData,
			       context->SecDir->Size - sizeof(cert->Hdr),
			       vendor_cert, sizeof(vendor_cert), hash,
			       SHA256_DIGEST_SIZE)) {
		status = EFI_SUCCESS;
		Print(L"Binary is verified by the vendor certificate\n");
		goto done;
	}

	status = get_variable(L"MokList", shim_lock_guid, &attributes,
			      &MokListDataSize, &MokListData);

	if (status != EFI_SUCCESS) {
		status = EFI_ACCESS_DENIED;
		Print(L"Invalid signature\n");
		goto done;
	}

	CopyMem(&MokNum, MokListData, sizeof(UINT32));
	if (MokNum == 0)
		goto done;

	list = build_mok_list(MokNum,
			      (void *)MokListData + sizeof(UINT32),
			      MokListDataSize - sizeof(UINT32));

	if (!list) {
		Print(L"Failed to construct MOK list\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	for (i = 0; i < MokNum; i++) {
		if (AuthenticodeVerify(cert->CertData,
				       context->SecDir->Size - sizeof(cert->Hdr),
				       list[i].Mok, list[i].MokSize, hash,
				       SHA256_DIGEST_SIZE)) {
			status = EFI_SUCCESS;
			Print(L"Binary is verified by the machine owner key\n");
			goto done;
		}
	}
	Print(L"Invalid signature\n");
	status = EFI_ACCESS_DENIED;

done:
	if (SectionHeader)
		FreePool(SectionHeader);
	if (ctx)
		FreePool(ctx);
	if (list)
		FreePool(list);
	if (MokListData)
		FreePool(MokListData);

	return status;
}

/*
 * Read the binary header and grab appropriate information from it
 */
static EFI_STATUS read_header(void *data,
			      PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	EFI_IMAGE_DOS_HEADER *DosHdr = data;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;

	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE)
		PEHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);

	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		Print(L"Unsupported image type\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		Print(L"Unsupported image - Relocations have been stripped\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Print(L"Only 64-bit images supported\n");
		return EFI_UNSUPPORTED;
	}

	context->PEHdr = PEHdr;
	context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
	context->ImageSize = (UINT64)PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
	context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
	context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
	context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;
	context->FirstSection = (EFI_IMAGE_SECTION_HEADER *)((char *)PEHdr + PEHdr->Pe32.FileHeader.SizeOfOptionalHeader + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER));
	context->SecDir = (EFI_IMAGE_DATA_DIRECTORY *) &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

	if (!secure_mode())
		return EFI_SUCCESS;

	if (context->SecDir->VirtualAddress >= context->ImageSize) {
		Print(L"Malformed security header\n");
		return EFI_INVALID_PARAMETER;
	}

	if (context->SecDir->Size == 0) {
		Print(L"Empty security header\n");
		return EFI_INVALID_PARAMETER;
	}

	return EFI_SUCCESS;
}

/*
 * Once the image has been loaded it needs to be validated and relocated
 */
static EFI_STATUS handle_grub (void *data, int datasize, EFI_LOADED_IMAGE *li)
{
	EFI_STATUS efi_status;
	char *buffer;
	int i, size;
	EFI_IMAGE_SECTION_HEADER *Section;
	char *base, *end;
	PE_COFF_LOADER_IMAGE_CONTEXT context;

	efi_status = read_header(data, &context);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to read header\n");
		return efi_status;
	}

	if (secure_mode ()) {
		efi_status = verify_buffer(data, datasize, &context, 0);

		if (efi_status != EFI_SUCCESS) {
			Print(L"Verification failed\n");
			return efi_status;
		}
	}

	buffer = AllocatePool(context.ImageSize);

	if (!buffer) {
		Print(L"Failed to allocate image buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}

	CopyMem(buffer, data, context.SizeOfHeaders);

	Section = context.FirstSection;
	for (i = 0; i < context.NumberOfSections; i++) {
		size = Section->Misc.VirtualSize;

		if (size > Section->SizeOfRawData)
			size = Section->SizeOfRawData;

		base = ImageAddress (buffer, context.ImageSize, Section->VirtualAddress);
		end = ImageAddress (buffer, context.ImageSize, Section->VirtualAddress + size - 1);

		if (!base || !end) {
			Print(L"Invalid section size\n");
			return EFI_UNSUPPORTED;
		}

		if (Section->SizeOfRawData > 0)
			CopyMem(base, data + Section->PointerToRawData, size);

		if (size < Section->Misc.VirtualSize)
			ZeroMem (base + size, Section->Misc.VirtualSize - size);

		Section += 1;
	}

	efi_status = relocate_coff(&context, buffer);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Relocation failed\n");
		FreePool(buffer);
		return efi_status;
	}

	entry_point = ImageAddress(buffer, context.ImageSize, context.EntryPoint);
	li->ImageBase = buffer;
	li->ImageSize = context.ImageSize;

	if (!entry_point) {
		Print(L"Invalid entry point\n");
		FreePool(buffer);
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS generate_path(EFI_LOADED_IMAGE *li, EFI_DEVICE_PATH **grubpath, CHAR16 **PathName)
{
	EFI_DEVICE_PATH *devpath;
	EFI_HANDLE device;
	int i;
	unsigned int pathlen = 0;
	EFI_STATUS efi_status = EFI_SUCCESS;
	CHAR16 *bootpath;

	device = li->DeviceHandle;
	devpath = li->FilePath;

	bootpath = DevicePathToStr(devpath);

	pathlen = StrLen(bootpath);

	for (i=pathlen; i>0; i--) {
		if (bootpath[i] == '\\')
			break;
	}

	bootpath[i+1] = '\0';

	if (bootpath[i-i] == '\\')
		bootpath[i] = '\0';

	*PathName = AllocatePool(StrSize(bootpath) + StrSize(SECOND_STAGE));

	if (!*PathName) {
		Print(L"Failed to allocate path buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	*PathName[0] = '\0';
	StrCat(*PathName, bootpath);
	StrCat(*PathName, SECOND_STAGE);

	*grubpath = FileDevicePath(device, *PathName);

error:
	return efi_status;
}

/*
 * Locate the second stage bootloader and read it into a buffer
 */
static EFI_STATUS load_grub (EFI_LOADED_IMAGE *li, void **data,
			     int *datasize, CHAR16 *PathName)
{
	EFI_GUID simple_file_system_protocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_GUID file_info_id = EFI_FILE_INFO_ID;
	EFI_STATUS efi_status;
	EFI_HANDLE device;
	EFI_FILE_INFO *fileinfo = NULL;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE *root, *grub;
	UINTN buffersize = sizeof(EFI_FILE_INFO);

	device = li->DeviceHandle;

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, device,
				       &simple_file_system_protocol, &drive);	

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to find fs\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to open fs\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(root->Open, 5, root, &grub, PathName,
				       EFI_FILE_MODE_READ, 0);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to open %s - %lx\n", PathName, efi_status);
		goto error;
	}

	fileinfo = AllocatePool(buffersize);

	if (!fileinfo) {
		Print(L"Unable to allocate file info buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	efi_status = uefi_call_wrapper(grub->GetInfo, 4, grub, &file_info_id,
				       &buffersize, fileinfo);

	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		fileinfo = AllocatePool(buffersize);
		if (!fileinfo) {
			Print(L"Unable to allocate file info buffer\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto error;
		}
		efi_status = uefi_call_wrapper(grub->GetInfo, 4, grub,
					       &file_info_id, &buffersize,
					       fileinfo);
	}

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to get file info\n");
		goto error;
	}

	buffersize = fileinfo->FileSize;

	*data = AllocatePool(buffersize);

	if (!*data) {
		Print(L"Unable to allocate file buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}
	efi_status = uefi_call_wrapper(grub->Read, 3, grub, &buffersize,
				       *data);

	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(buffersize);
		efi_status = uefi_call_wrapper(grub->Read, 3, grub,
					       &buffersize, *data);
	}

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unexpected return from initial read: %x, buffersize %x\n", efi_status, buffersize);
		goto error;
	}

	*datasize = buffersize;

	return EFI_SUCCESS;
error:
	if (*data) {
		FreePool(*data);
		*data = NULL;
	}
	if (PathName)
		FreePool(PathName);
	if (fileinfo)
		FreePool(fileinfo);
	return efi_status;
}

EFI_STATUS shim_verify (void *buffer, UINT32 size)
{
	EFI_STATUS status;
	PE_COFF_LOADER_IMAGE_CONTEXT context;

	if (!secure_mode())
		return EFI_SUCCESS;

	status = read_header(buffer, &context);

	if (status != EFI_SUCCESS)
		return status;

	status = verify_buffer(buffer, size, &context, 1);

	return status;
}

EFI_STATUS init_grub(EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;
	EFI_HANDLE grub_handle = NULL;
	EFI_LOADED_IMAGE *li, li_bak;
	EFI_DEVICE_PATH *grubpath;
	CHAR16 *PathName;
	EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
	void *data = NULL;
	int datasize;

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, image_handle,
				       &loaded_image_protocol, &li);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to init protocol\n");
		return efi_status;
	}

	efi_status = generate_path(li, &grubpath, &PathName);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to generate grub path\n");
		goto done;
	}

	efi_status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, image_handle,
				       grubpath, NULL, 0, &grub_handle);


	if (efi_status == EFI_SUCCESS) {
		/* Image validates - start it */
		Print(L"Starting file via StartImage\n");
		efi_status = uefi_call_wrapper(BS->StartImage, 3, grub_handle, NULL,
					       NULL);
		uefi_call_wrapper(BS->UnloadImage, 1, grub_handle);
		goto done;
	}

	efi_status = load_grub(li, &data, &datasize, PathName);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to load grub\n");
		goto done;
	}

	CopyMem(&li_bak, li, sizeof(li_bak));

	efi_status = handle_grub(data, datasize, li);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to load grub\n");
		CopyMem(li, &li_bak, sizeof(li_bak));
		goto done;
	}

	efi_status = uefi_call_wrapper(entry_point, 3, image_handle, systab);

	CopyMem(li, &li_bak, sizeof(li_bak));
done:

	return efi_status;
}

static void print_x509_name (X509_NAME *X509Name, char *name)
{
	char *str;

	str = X509_NAME_oneline(X509Name, NULL, 0);
	if (str) {
		APrint((CHAR8 *)"%a: %a\n", name, str);
		OPENSSL_free(str);
	}
}

static const char *mon[12]= {
"Jan","Feb","Mar","Apr","May","Jun",
"Jul","Aug","Sep","Oct","Nov","Dec"
};

static void print_x509_GENERALIZEDTIME_time (ASN1_TIME *time, char *name) {
	char *v;
	int gmt = 0;
	int i;
	int y = 0,M = 0,d = 0,h = 0,m = 0,s = 0;
	char *f = NULL;
	int f_len = 0;

	i=time->length;
	v=(char *)time->data;

	if (i < 12)
		goto error;

	if (v[i-1] == 'Z')
		gmt=1;

	for (i=0; i<12; i++) {
		if ((v[i] > '9') || (v[i] < '0'))
			goto error;
	}

	y = (v[0]-'0')*1000+(v[1]-'0')*100 + (v[2]-'0')*10+(v[3]-'0');
	M = (v[4]-'0')*10+(v[5]-'0');

	if ((M > 12) || (M < 1))
		goto error;

	d = (v[6]-'0')*10+(v[7]-'0');
	h = (v[8]-'0')*10+(v[9]-'0');
	m = (v[10]-'0')*10+(v[11]-'0');

	if (time->length >= 14 &&
	    (v[12] >= '0') && (v[12] <= '9') &&
	    (v[13] >= '0') && (v[13] <= '9')) {
		s = (v[12]-'0')*10+(v[13]-'0');
		/* Check for fractions of seconds. */
		if (time->length >= 15 && v[14] == '.')	{
			int l = time->length;
			f = &v[14];	/* The decimal point. */
			f_len = 1;
			while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
				++f_len;
		}
	}

	APrint((CHAR8 *)"%a: %a %2d %02d:%02d:%02d%.*a %d%a",
	       name, mon[M-1],d,h,m,s,f_len,f,y,(gmt)?" GMT":"");
error:
	return;
}

static void print_x509_UTCTIME_time (ASN1_TIME *time, char *name)
{
	char *v;
	int gmt=0;
	int i;
	int y = 0,M = 0,d = 0,h = 0,m = 0,s = 0;

	i=time->length;
	v=(char *)time->data;

	if (i < 10)
		goto error;

	if (v[i-1] == 'Z')
		gmt=1;

	for (i=0; i<10; i++)
		if ((v[i] > '9') || (v[i] < '0'))
			goto error;

	y = (v[0]-'0')*10+(v[1]-'0');

	if (y < 50)
		y+=100;

	M = (v[2]-'0')*10+(v[3]-'0');

	if ((M > 12) || (M < 1))
		goto error;

	d = (v[4]-'0')*10+(v[5]-'0');
	h = (v[6]-'0')*10+(v[7]-'0');
	m = (v[8]-'0')*10+(v[9]-'0');

	if (time->length >=12 &&
	    (v[10] >= '0') && (v[10] <= '9') &&
	    (v[11] >= '0') && (v[11] <= '9'))
		s = (v[10]-'0')*10+(v[11]-'0');

	APrint((CHAR8 *)"%a: %a %2d %02d:%02d:%02d %d%a\n",
	       name, mon[M-1],d,h,m,s,y+1900,(gmt)?" GMT":"");
error:
	return;
}

static void print_x509_time (ASN1_TIME *time, char *name)
{
	if(time->type == V_ASN1_UTCTIME)
		print_x509_UTCTIME_time(time, name);

	if(time->type == V_ASN1_GENERALIZEDTIME)
		print_x509_GENERALIZEDTIME_time(time, name);
}

static void show_x509_info (X509 *X509Cert)
{
	X509_NAME *X509Name;
	ASN1_TIME *time;

	X509Name = X509_get_issuer_name(X509Cert);
	if (X509Name) {
		print_x509_name(X509Name, "Issuer");
	}

	X509Name = X509_get_subject_name(X509Cert);
	if (X509Name) {
		print_x509_name(X509Name, "Subject");
	}

	time = X509_get_notBefore(X509Cert);
	if (time) {
		print_x509_time(time, "Not Before");
	}

	time = X509_get_notAfter(X509Cert);
	if (time) {
		print_x509_time(time, "Not After");
	}
}

static void show_mok_info (void *Mok, UINTN MokSize)
{
	EFI_STATUS efi_status;
	UINT8 hash[SHA256_DIGEST_SIZE];
	unsigned int i;
	X509 *X509Cert;

	if (!Mok || MokSize == 0)
		return;

	efi_status = get_sha256sum(Mok, MokSize, hash);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to compute MOK fingerprint\n");
		return;
	}

	if (X509ConstructCertificate(Mok, MokSize, (UINT8 **) &X509Cert) &&
	    X509Cert != NULL) {
		show_x509_info(X509Cert);
		X509_free(X509Cert);
	}

	Print(L"Fingerprint (SHA256):\n");
	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		Print(L" %02x", hash[i]);
		if (i % 16 == 15)
			Print(L"\n");
	}
}

static UINT8 delete_mok(MokListNode *list, UINT32 MokNum, UINT32 delete)
{
	if (!list || !MokNum || MokNum <= delete)
		return 0;

	list[delete].Mok = NULL;
	list[delete].MokSize = 0;

	return 1;
}

static UINT8 mok_deletion_prompt(MokListNode *list, UINT32 MokNum)
{
	EFI_INPUT_KEY key;
	CHAR16 line[10];
	unsigned int word_count = 0;
	UINTN delete;

	Print(L"delete key: ");
	do {
		key = get_keystroke();
		if ((key.UnicodeChar < '0' ||
		     key.UnicodeChar > '9' ||
		     word_count >= 10) &&
		    key.UnicodeChar != CHAR_BACKSPACE)
			continue;

		if (word_count == 0 && key.UnicodeChar == CHAR_BACKSPACE)
			continue;

		Print(L"%c", key.UnicodeChar);

		if (key.UnicodeChar == CHAR_BACKSPACE) {
			word_count--;
			line[word_count] = '\0';
			continue;
		}

		line[word_count] = key.UnicodeChar;
		word_count++;
	} while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);
	Print(L"\n");

	if (word_count == 0)
		return 0;

	line[word_count] = '\0';
	delete = Atoi(line)-1;

	if (delete >= MokNum) {
		Print(L"No such key\n");
		return 0;
	}

	if (!list[delete].Mok) {
		Print(L"Already deleted\n");
		return 0;
	}

	Print(L"Delete this key?\n");
	show_mok_info(list[delete].Mok, list[delete].MokSize);
	Print(L"(y/N) ");
	key = get_keystroke();
	if (key.UnicodeChar != 'y' && key.UnicodeChar != 'Y') {
		Print(L"N\nAbort\n");
		return 0;
	}
	Print(L"y\nDelete key %d\n", delete+1);

	return delete_mok(list, MokNum, delete);
}

static void write_mok_list(void *MokListData, UINTN MokListDataSize,
			   MokListNode *list, UINT32 MokNum)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS efi_status;
	UINT32 new_num = 0;
	unsigned int i;
	UINTN DataSize = 0;
	void *Data, *ptr;

	if (!MokListData || !list)
		return;

	for (i = 0; i < MokNum; i++) {
		if (list[i].Mok && list[i].MokSize > 0) {
			DataSize += list[i].MokSize + sizeof(UINT32);
			if (new_num < i) {
				list[new_num].Mok = list[i].Mok;
				list[new_num].MokSize = list[i].MokSize;
			}
			new_num++;
		}
	}

	if (new_num == 0) {
		Data = NULL;
		goto done;
	}

	DataSize += sizeof(UINT32);

	Data = AllocatePool(DataSize * sizeof(UINT8));
	ptr = Data;

	CopyMem(Data, &new_num, sizeof(new_num));
	ptr += sizeof(new_num);

	for (i = 0; i < new_num; i++) {
		CopyMem(ptr, &list[i].MokSize, sizeof(list[i].MokSize));
		ptr += sizeof(list[i].MokSize);
		CopyMem(ptr, list[i].Mok, list[i].MokSize);
		ptr += list[i].MokSize;
	}

done:
	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"MokList",
				       &shim_lock_guid,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				       DataSize, Data);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to set variable %d\n", efi_status);
	}

	if (Data)
		FreePool(Data);
}

static void mok_mgmt_shell (void)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS efi_status;
	unsigned int i, changed = 0;
	void *MokListData = NULL;
	UINTN MokListDataSize = 0;
	UINT32 MokNum;
	UINT32 attributes;
	MokListNode *list = NULL;
	EFI_INPUT_KEY key;

	efi_status = get_variable(L"MokList", shim_lock_guid, &attributes,
				  &MokListDataSize, &MokListData);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to get MokList\n");
		goto error;
	}

	CopyMem(&MokNum, MokListData, sizeof(UINT32));
	if (MokNum == 0) {
		Print(L"No key enrolled\n");
		goto error;
	}
	list = build_mok_list(MokNum,
			      (void *)MokListData + sizeof(UINT32),
			      MokListDataSize - sizeof(UINT32));

	if (!list) {
		Print(L"Failed to construct MOK list\n");
		goto error;
	}

	do {
		Print(L" \'c\' to continue) ");
		key = get_keystroke();
		Print(L"%c\n", key.UnicodeChar);

		switch (key.UnicodeChar) {
			case 'l':
			case 'L':
				for (i = 0; i < MokNum; i++) {
					if (list[i].Mok) {
						Print(L"Key %d\n", i+1);
						show_mok_info(list[i].Mok, list[i].MokSize);
						Print(L"\n");
					}
				}
				break;
			case 'd':
			case 'D':
				if (mok_deletion_prompt(list, MokNum) && changed == 0)
					changed = 1;
				break;
		}
	} while (key.UnicodeChar != 'c' && key.UnicodeChar != 'C');

	if (changed) {
		write_mok_list(MokListData, MokListDataSize, list, MokNum);
	}

error:
	if (MokListData)
		FreePool(MokListData);
	if (list)
		FreePool(list);
}

static UINT8 mok_enrollment_prompt (void *Mok, UINTN MokSize)
{
	EFI_INPUT_KEY key;

	Print(L"New machine owner key:\n\n");
	show_mok_info(Mok, MokSize);
	Print(L"\nEnroll the key? (y/N): ");

	key = get_keystroke();
	Print(L"%c\n", key.UnicodeChar);

	if (key.UnicodeChar == 'Y' || key.UnicodeChar == 'y') {
		return 1;
	}

	Print(L"Abort\n");

	return 0;
}

static EFI_STATUS enroll_mok (void *Mok, UINT32 MokSize, void *OldData,
			      UINT32 OldDataSize, UINT32 MokNum)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS efi_status;
	void *Data, *ptr;
	UINT32 DataSize = 0;

	if (OldData)
		DataSize += OldDataSize;
	else
		DataSize += sizeof(UINT32);
	DataSize += sizeof(UINT32);
	DataSize += MokSize;
	MokNum += 1;

	Data = AllocatePool(DataSize);

	if (!Data) {
		Print(L"Failed to allocate buffer for MOK list\n");
		return EFI_OUT_OF_RESOURCES;
	}

	ptr = Data;

	if (OldData) {
		CopyMem(ptr, OldData, OldDataSize);
		CopyMem(ptr, &MokNum, sizeof(MokNum));
		ptr += OldDataSize;
	} else {
		CopyMem(ptr, &MokNum, sizeof(MokNum));
		ptr += sizeof(MokNum);
	}

	/* Write new MOK */
	CopyMem(ptr, &MokSize, sizeof(MokSize));
	ptr += sizeof(MokSize);
	CopyMem(ptr, Mok, MokSize);

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"MokList",
				       &shim_lock_guid,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				       DataSize, Data);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to set variable %d\n", efi_status);
		goto error;
	}

error:
	if (Data)
		FreePool(Data);

	return efi_status;
}

static void check_mok_request(EFI_HANDLE image_handle)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS efi_status;
	UINTN uint8size = sizeof(UINT8);
	UINT8 MokMgmt;
	UINTN MokSize = 0, MokListDataSize = 0;
	void *Mok = NULL, *MokListData = NULL;
	UINT32 MokNum = 0;
	UINT32 attributes;
	MokListNode *list = NULL;
	UINT8 confirmed;

	if (!secure_mode())
		return;

	efi_status = get_variable(L"MokMgmt", shim_lock_guid, &attributes,
				  &uint8size, (void *)&MokMgmt);

	if (efi_status == EFI_SUCCESS && MokMgmt == 1) {
		mok_mgmt_shell();
		if (delete_variable(L"MokMgmt", shim_lock_guid) != EFI_SUCCESS) {
			Print(L"Failed to delete MokMgmt\n");
		}
	}

	efi_status = get_variable(L"MokNew", shim_lock_guid, &attributes,
				  &MokSize, &Mok);

	if (efi_status != EFI_SUCCESS) {
		goto error;
	}

	efi_status = get_variable(L"MokList", shim_lock_guid, &attributes,
				  &MokListDataSize, &MokListData);

	if (efi_status == EFI_SUCCESS && MokListData) {
		int i;

		CopyMem(&MokNum, MokListData, sizeof(UINT32));
		list = build_mok_list(MokNum,
				      (void *)MokListData + sizeof(UINT32),
				      MokListDataSize - sizeof(UINT32));

		if (!list) {
			Print(L"Failed to construct MOK list\n");
			goto error;
		}

		/* check if the key is already enrolled */
		for (i = 0; i < MokNum; i++) {
			if (list[i].MokSize == MokSize &&
			    CompareMem(list[i].Mok, Mok, MokSize) == 0) {
				Print(L"MOK was already enrolled\n");
				goto error;
			}
		}
	}

	confirmed = mok_enrollment_prompt(Mok, MokSize);

	if (!confirmed)
		goto error;

	efi_status = enroll_mok(Mok, MokSize, MokListData,
				MokListDataSize, MokNum);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll MOK\n");
		goto error;
	}

error:
	if (Mok) {
		if (delete_variable(L"MokNew", shim_lock_guid) != EFI_SUCCESS) {
			Print(L"Failed to delete MokNew\n");
		}
		FreePool (Mok);
	}

	if (list)
		FreePool (list);

	if (MokListData)
		FreePool (MokListData);
}

EFI_STATUS efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *passed_systab)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	static SHIM_LOCK shim_lock_interface;
	EFI_HANDLE handle = NULL;
	EFI_STATUS efi_status;

	shim_lock_interface.Verify = shim_verify;

	systab = passed_systab;

	InitializeLib(image_handle, systab);

	check_mok_request(image_handle);

	uefi_call_wrapper(BS->InstallProtocolInterface, 4, &handle,
			  &shim_lock_guid, EFI_NATIVE_INTERFACE,
			  &shim_lock_interface);

	efi_status = init_grub(image_handle);

	uefi_call_wrapper(BS->UninstallProtocolInterface, 3, handle,
			  &shim_lock_guid, &shim_lock_interface);

	return efi_status;
}
