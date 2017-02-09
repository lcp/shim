/*
 * Copyright 2017 SUSE LINUX GmbH <glin@suse.com>
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
 */

#include <efi.h>
#include <efilib.h>
#include <Library/BaseCryptLib.h>

#include "shim.h"
#include "shim_cert.h"
#include "svlist.h"

#include "PeImage.h"
#include "console.h"
#include "variables.h"
#include "guid.h"

extern UINT8 in_protocol;

#define perror(fmt, ...) ({						\
		UINTN __perror_ret = 0;					\
		if (!in_protocol)					\
			__perror_ret = Print((fmt), ##__VA_ARGS__);	\
		__perror_ret;						\
	})

#define NEW_LIST_SIZE (sizeof(svlist_t) + sizeof(svnode_t))

extern UINT32 vendor_cert_size;
extern UINT8 *vendor_cert;

#define EFI_IMAGE_SECURITY_DATABASE_GUID { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }}

extern UINT8 user_insecure_mode;
UINT8 sv_verify;

static EFI_STATUS unknown_signer_prompt()
{
	CHAR16 *lines[4];

	lines[0] = L"Booting a image with an unknown signer";
	lines[1] = L"";
	lines[2] = L"Do you want to boot this image?";
	lines[3] = NULL;

	setup_console(1);
	if (console_yes_no(lines))
		return EFI_SUCCESS;

	return EFI_ACCESS_DENIED;
}

static inline EFI_STATUS set_svlist(UINT8 *data, UINTN size)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	return uefi_call_wrapper(RT->SetVariable, 5,
				 L"SVList",
				 &shim_lock_guid,
				 EFI_VARIABLE_NON_VOLATILE
				 | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				 size, data);
}

static EFI_STATUS lower_sv_prompt(const UINT32 signer, const UINT16 dv,
				  const UINT16 sv, UINT8 **sl_data,
				  UINTN *sl_size, svnode_t *node)
{
	CHAR16 *lines[10];
	CHAR16 signer_l[80], dv_l[80], sv_l1[80], sv_l2[80];
	CHAR8 *ptr;

	if (!node)
		return EFI_ACCESS_DENIED;

	ptr = (CHAR8 *)&signer;
	SPrint(signer_l, 80, L"Signer Name: %c%c%c%c", ptr[0], ptr[1],
						       ptr[2], ptr[3]);
	SPrint(dv_l, 80, L"Distro Version: %d", dv);
	SPrint(sv_l1, 80, L"Accepted Security Version: %d", node->sv);
	SPrint(sv_l2, 80, L"Security Version of this image: %d", sv);

	lines[0] = L"Booting a less secure image";
	lines[1] = L"";
	lines[2] = signer_l;
	lines[3] = dv_l;
	lines[4] = L"";
	lines[5] = sv_l1;
	lines[6] = sv_l2;
	lines[7] = L"";
	lines[8] = L"Do you want to lower the security version?";
	lines[9] = NULL;

	setup_console(1);
	if (console_yes_no(lines) == 0)
		return EFI_ACCESS_DENIED;

	node->sv = sv;
	return set_svlist(*sl_data, *sl_size);
}

/*
 * Find the list that matches the signer
 */
static svlist_t *match_signer(const UINT8 *data, const UINTN datasize,
			      const UINT32 signer, UINTN *offset)
{
	svlist_t *list;
	UINTN skip = 0;

	while (skip < datasize) {
		list = (svlist_t *)(data + skip);

		if (CompareMem(list->signer, &signer, 4) != 0) {
			skip += list->size;
			continue;
		}

		*offset = skip;
		return list;
	}

	return NULL;
}

static EFI_STATUS new_sv_prompt(const UINT32 signer, const UINT16 dv,
				const UINT16 sv, UINT8 **sl_data,
				UINTN *sl_size, svlist_t *list, UINTN offset)
{
	CHAR16 *lines[8];
	CHAR16 signer_l[80], dv_l[80], sv_l[80];
	CHAR8 *ptr;
	UINT8 *new_sl_data;

	ptr = (CHAR8 *)&signer;
	SPrint(signer_l, 80, L"Signer Name: %c%c%c%c", ptr[0], ptr[1],
						       ptr[2], ptr[3]);
	SPrint(dv_l, 80, L"Distro Version: %d", dv);
	SPrint(sv_l, 80, L"Security Version: %d", sv);

	if (list)
		lines[0] = L"Booting a image with a new distro version";
	else
		lines[0] = L"Booting a image with a new signer";
	lines[1] = L"";
	lines[2] = signer_l;
	lines[3] = dv_l;
	lines[4] = sv_l;
	lines[5] = L"";
	lines[6] = L"Do you want to accept this image?";
	lines[7] = NULL;

	setup_console(1);
	if (console_yes_no(lines) == 0)
		return EFI_ACCESS_DENIED;

	if (list) {
		UINTN skip, remaining;
		UINT32 list_n;

		new_sl_data = AllocatePool(*sl_size + sizeof(svnode_t));
		if (!new_sl_data)
			return EFI_OUT_OF_RESOURCES;

		skip = offset + list->size;
		remaining = *sl_size - skip;
		list_n = count_nodes(list);

		CopyMem(new_sl_data, *sl_data, skip);
		if (remaining > 0) {
			CopyMem(new_sl_data + skip + sizeof(svnode_t),
				*sl_data + skip, remaining);
		}

		list = (svlist_t *)(new_sl_data + offset);
		list->size += sizeof(svnode_t);
		list->nodes[list_n].dv = dv;
		list->nodes[list_n].sv = sv;

		FreePool(*sl_data);
		*sl_data = new_sl_data;
		*sl_size += sizeof(svnode_t);
	} else {
		new_sl_data = AllocatePool(*sl_size + NEW_LIST_SIZE);
		if (!new_sl_data)
			return EFI_OUT_OF_RESOURCES;

		CopyMem(new_sl_data, *sl_data, *sl_size);

		list = (svlist_t *)(new_sl_data + *sl_size);
		list->size = NEW_LIST_SIZE;
		CopyMem(list->signer, &signer, 4);
		list->nodes[0].dv = dv;
		list->nodes[0].sv = sv;

		FreePool(*sl_data);
		*sl_data = new_sl_data;
		*sl_size += NEW_LIST_SIZE;
	}

	return set_svlist(*sl_data, *sl_size);
}

/*
 * Match the sum of the sizes in the list headers and the size of the variable
 */
static BOOLEAN verify_svlist_data(const UINT8 *data, const UINTN size)
{
	svlist_t *lptr;
	UINTN offset = 0;

	while (offset < size) {
		lptr = (svlist_t *)(data + offset);
		offset += lptr->size;
	}

	if (offset != size)
		return FALSE;

	return TRUE;
}

/*
 * Load the content of SVList, check the attributes of the variable, and
 * verify the content.
 */
static EFI_STATUS load_svlist(UINT8 **data, UINTN *size)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	UINT32 attributes;
	EFI_STATUS status;

	status = get_variable_attr(L"SVList", data, size,
				   shim_lock_guid, &attributes);
	if (status != EFI_SUCCESS)
		goto exit;

	/* If SVList isn't RT accessible and the content is fine,
	 * then it's done. */
	if (!(attributes & EFI_VARIABLE_RUNTIME_ACCESS) &&
	    verify_svlist_data(*data, *size))
		return EFI_SUCCESS;

	/* Free data and delete SVList since it's invalid or compromised. */
	FreePool(*data);
	status = LibDeleteVariable(L"SVList", &shim_lock_guid);
	if (status != EFI_SUCCESS)
		goto exit;

	status = EFI_NOT_FOUND;
exit:
	*data = NULL;
	*size = 0;
	return status;
}

/*
 * Find the node that matches the distro version
 */
static svnode_t *match_dv(svlist_t *list, UINT16 dv)
{
	UINTN i, list_n;

	list_n = count_nodes(list);
	for (i = 0; i < list_n; i++) {
		if (list->nodes[i].dv == dv)
			return &(list->nodes[i]);
	}

	return NULL;
}

/*
 * Copy the boot-services only SVList variable to the runtime-accessible
 * SVListRT variable. It's not marked NV, so the OS can't modify it.
 */
static EFI_STATUS mirror_svlist()
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS status;
	UINT8 *Data = NULL;
	UINTN DataSize = 0;

	status = load_svlist(&Data, &DataSize);
	if (status != EFI_SUCCESS)
		return status;

	status = uefi_call_wrapper(RT->SetVariable, 5, L"SVListRT",
				   &shim_lock_guid,
				   EFI_VARIABLE_BOOTSERVICE_ACCESS
				   | EFI_VARIABLE_RUNTIME_ACCESS,
				   DataSize, Data);
	if (status != EFI_SUCCESS) {
		console_error(L"Failed to set SVListRT", status);
	}

	return status;
}

/*
 * Check the Security version of the image
 */
EFI_STATUS check_security_version(const EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr)
{
	EFI_STATUS status;
	UINT8 *sl_data = NULL;
	UINTN sl_size = 0;
	UINT32 signer;
	UINT16 dv, sv;
	svlist_t *list;

	if (sv_verify == 0)
		return EFI_SUCCESS;

	if (image_is_64_bit(PEHdr)) {
		dv = PEHdr->Pe32Plus.OptionalHeader.MajorImageVersion;
		sv = PEHdr->Pe32Plus.OptionalHeader.MinorImageVersion;
		signer = PEHdr->Pe32Plus.OptionalHeader.MajorOperatingSystemVersion |
			 PEHdr->Pe32Plus.OptionalHeader.MinorOperatingSystemVersion << 16;
	} else {
		dv = PEHdr->Pe32.OptionalHeader.MajorImageVersion;
		sv = PEHdr->Pe32.OptionalHeader.MinorImageVersion;
		signer = PEHdr->Pe32.OptionalHeader.MajorOperatingSystemVersion |
			 PEHdr->Pe32.OptionalHeader.MinorOperatingSystemVersion << 16;
	}

	/* The signer is unknown */
	if (signer == 0)
		return unknown_signer_prompt();

	/* Load the security version list from SVList */
	status = load_svlist(&sl_data, &sl_size);

	if (status == EFI_SUCCESS) {
		/* The security version list exists, so only allow the image
		 * with the same or higher security version to boot.
		 * If (1) the signer or the distro version do not exist in
		 * the list or (2) the image has the lower security version,
		 * show a warning prompt to the user. */
		svnode_t *node;
		UINTN offset;

		list = match_signer(sl_data, sl_size, signer, &offset);
		if (!list || !(node = match_dv(list, dv))) {
			status = new_sv_prompt(signer, dv, sv, &sl_data,
					       &sl_size, list, offset);
			goto exit;
		}

		if (sv == node->sv) {
			/* The image has the same security version. */
			status = EFI_SUCCESS;
		} else if (sv > node->sv) {
			/* The image has the higher security version.
			 * Update the list. */
			node->sv = sv;
			status = set_svlist(sl_data, sl_size);
		} else {
			status = lower_sv_prompt(signer, dv, sv, &sl_data,
						 &sl_size, node);
		}
	} else if (status == EFI_NOT_FOUND) {
		/* The list is empty. Create a new list based on this image. */
		UINT8 new[NEW_LIST_SIZE];

		list = (svlist_t *)new;
		CopyMem(list->signer, &signer, 4);
		list->size = NEW_LIST_SIZE;
		list->nodes[0].dv = dv;
		list->nodes[0].sv = sv;

		status = set_svlist(new, NEW_LIST_SIZE);
	}

exit:
	if (sl_data)
		FreePool(sl_data);

	if (status == EFI_SUCCESS)
		mirror_svlist();

	return status;
}

static BOOLEAN verify_sig_cert_list(EFI_SIGNATURE_LIST *CertList, UINTN dbsize,
				    const UINT8 *data, const UINTN datasize,
				    const UINT8 *sig, const UINTN sigsize)
{
	EFI_SIGNATURE_DATA *Cert;
	UINTN CertSize;
	BOOLEAN IsFound = FALSE;
	EFI_GUID CertType = X509_GUID;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if (CompareGuid (&CertList->SignatureType, &CertType) == 0) {
			Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)CertList +
			       sizeof(EFI_SIGNATURE_LIST) +
			       CertList->SignatureHeaderSize);
			CertSize = CertList->SignatureSize - sizeof(EFI_GUID);
			if (verify_x509(Cert->SignatureData, CertSize)) {
				IsFound = Pkcs7Verify(sig, sigsize,
						      Cert->SignatureData,
						      CertSize,
						      data, datasize);
				if (IsFound)
					return TRUE;
			}
		}

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *)((UINT8 *)CertList +
			   CertList->SignatureListSize);
	}

	return FALSE;
}

static BOOLEAN verify_sig_db_var(CHAR16 *dbname, const EFI_GUID guid,
				 const UINT8 *data, const UINTN datasize,
				 const UINT8 *sig, const UINTN sigsize)
{
	EFI_SIGNATURE_LIST *CertList;
	BOOLEAN result;
	UINTN dbsize = 0;
	UINT8 *db;

	if (get_variable(dbname, &db, &dbsize, guid) != EFI_SUCCESS)
		return FALSE;

	CertList = (EFI_SIGNATURE_LIST *)db;
	result = verify_sig_cert_list(CertList, dbsize, data, datasize, sig,
				      sigsize);

	FreePool(db);

	return result;
}

static BOOLEAN verify_svlistsig(const UINT8 *SVNew, const UINTN SVNewSize,
				const UINT8 *SVSig, const UINTN SVSigSize)
{
	EFI_GUID shim_var = SHIM_LOCK_GUID;
	BOOLEAN result;

	if (verify_mok() != EFI_SUCCESS)
		return FALSE;

	if (verify_sig_db_var(L"MokList", shim_var, SVNew, SVNewSize,
			      SVSig, SVSigSize) == TRUE)
		return TRUE;

	if (sizeof(shim_cert)) {
		result = Pkcs7Verify(SVSig, SVSigSize,
				     shim_cert, sizeof(shim_cert),
				     SVNew, SVNewSize);
		if (result)
			return TRUE;
	}

	if (vendor_cert_size) {
		result = Pkcs7Verify(SVSig, SVSigSize,
				     vendor_cert, vendor_cert_size,
				     SVNew, SVNewSize);
		if (result)
			return TRUE;
	}

	return FALSE;
}

static EFI_STATUS merge_new_nodes(UINT8 *data, UINTN *size, const UINTN offset,
				  svlist_t *cur, const svlist_t *new)
{
	UINTN i, j, cur_n, new_n, extra;
	UINT8 *merged;

	cur_n = count_nodes(cur);
	new_n = count_nodes(new);
	extra = new_n;

	merged = AllocateZeroPool(new_n);
	if (!merged)
		return EFI_OUT_OF_RESOURCES;

	/* 1st round
	 * Update the current list if necessary and mark the node as merged */
	for (i = 0; i < new_n; i++) {
		for (j = 0; j < cur_n; j++) {
			if (new->nodes[i].dv != cur->nodes[j].dv)
				continue;

			/* The node with the same distro version exists in
			 * the current list. Update the current node if
			 * necessary */
			if (new->nodes[i].sv > cur->nodes[j].sv)
				cur->nodes[j].sv = new->nodes[i].sv;
			merged[i] = 1;
			extra--;
			break;
		}
	}

	/* Check if all nodes from "new" are done */
	if (extra == 0)
		goto exit;

	/* There are "extra" nodes to be appended to the "cur" list, so we need
	 * to move the remaining data "extra * sizeof(svnode_t)" bytes away
	 * from the "cur" list. */
	UINTN off_s = offset + cur->size;
	UINT8 *src = (UINT8 *)(data + off_s);
	UINT8 *dst = (UINT8 *)(src + extra * sizeof(svnode_t));
	for (i = *size - off_s; i > 0; i--)
		dst[i-1] = src[i-1];

	/* 2nd round
	 * Append the unmerged nodes */
	cur->size += extra * sizeof(svnode_t);
	*size += extra * sizeof(svnode_t);
	for (i = new_n; i > 0; i--) {
		if (merged[i-1])
			continue;

		extra--;
		cur->nodes[cur_n + extra].dv = new->nodes[i-1].dv;
		cur->nodes[cur_n + extra].sv = new->nodes[i-1].sv;
	}

exit:
	FreePool(merged);

	return EFI_SUCCESS;
}

static EFI_STATUS merge_svlistnew(const UINT8 *SVNew, const UINTN SVNewSize)
{
	EFI_STATUS status;
	UINT8 *old_var = NULL, *new_var = NULL;
	UINTN old_var_size, new_var_size;
	svlist_t *cur_lptr, *new_lptr;
	UINTN off_v = 0, off_n = 0;
	UINT32 *signer;

	status = load_svlist(&old_var, &old_var_size);
	if (status != EFI_SUCCESS && status != EFI_NOT_FOUND)
		return status;

	/* Allocate the memory for new_var. The maximum size we need is the size of
	 * SVList plus the size of SVListNew, i.e. appending SVListNew to SVList. */
	new_var = AllocatePool(old_var_size + SVNewSize);
	if (!new_var) {
		status = EFI_OUT_OF_RESOURCES;
		goto exit;
	}
	new_var_size = old_var_size;
	if (old_var)
		CopyMem(new_var, old_var, old_var_size);

	while (off_n < SVNewSize) {
		new_lptr = (svlist_t *)(SVNew + off_n);
		if ((off_n + new_lptr->size) > SVNewSize) {
			status = EFI_INVALID_PARAMETER;
			goto exit;
		}

		signer = (UINT32 *)new_lptr->signer;
		cur_lptr = match_signer(new_var, new_var_size, *signer, &off_v);
		if (cur_lptr) {
			/* The signer exists in SVList. Merge the nodes. */
			status = merge_new_nodes(new_var, &new_var_size, off_v,
						 cur_lptr, new_lptr);
			if (status != EFI_SUCCESS)
				goto exit;
		} else {
			/* The signer doesn't exist. Append the list */
			CopyMem(new_var + new_var_size, new_lptr, new_lptr->size);
			new_var_size += cur_lptr->size;
		}

		off_n += new_lptr->size;
	}

	/* Write the variable */
	status = set_svlist(new_var, new_var_size);

exit:
	if (old_var)
		FreePool(old_var);

	if (new_var)
		FreePool(new_var);

	return status;
}

/*
 * Check SVListNew and SVListSig and merge the list
 */
EFI_STATUS check_svlist_request()
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS status;
	UINT8 *SVNew = NULL, *SVSig = NULL;
	UINTN SVNewSize, SVSigSize;

	status = get_variable(L"SVListNew", &SVNew, &SVNewSize,
			      shim_lock_guid);
	if (status != EFI_SUCCESS)
		return status;

	status = LibDeleteVariable(L"SVListNew", &shim_lock_guid);
	if (status != EFI_SUCCESS) {
		console_notify(L"Failed to delete SVListNew");
		goto exit;
	}

	/* SVListSig must exist */
	status = get_variable(L"SVListSig", &SVSig, &SVSigSize,
			      shim_lock_guid);
	if (status != EFI_SUCCESS)
		goto exit;

	status = LibDeleteVariable(L"SVListSig", &shim_lock_guid);
	if (status != EFI_SUCCESS) {
		console_notify(L"Failed to delete SVListSig");
		goto exit;
	}

	/* If SVList is deleted, there is no need to check SVListNew */
	if (!sv_verify)
		goto exit;

	if (!verify_svlist_data(SVNew, SVNewSize)) {
		status = EFI_INVALID_PARAMETER;
		goto exit;
	}

	if (!verify_svlistsig(SVNew, SVNewSize, SVSig, SVSigSize)) {
		status = EFI_INVALID_PARAMETER;
		goto exit;
	}

	status = merge_svlistnew(SVNew, SVNewSize);

exit:
	if (SVNew)
		FreePool(SVNew);

	if (SVSig)
		FreePool(SVSig);

	return status;
}

/*
 * Check the device path and set sv_verify
 */
EFI_STATUS check_boot_device(const EFI_HANDLE image_handle)
{
	EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_DEVICE_PATH *devpath, *Node;
	EFI_LOADED_IMAGE *li;
	BOOLEAN hdd = FALSE, usb = FALSE;
	UINTN var_size = sizeof(UINT8);
	UINT8 var;
	UINT32 attributes;
	EFI_STATUS status;

	if (user_insecure_mode) {
		sv_verify = 0;
		return EFI_SUCCESS;
	}

	/*
	 * We need to refer to the loaded image protocol on the running
	 * binary in order to find our path
	 */
	status = uefi_call_wrapper(BS->HandleProtocol, 3, image_handle,
				   &loaded_image_protocol, (void **)&li);

	if (status != EFI_SUCCESS) {
		perror(L"Unable to init protocol\n");
		return status;
	}

	devpath = DevicePathFromHandle(li->DeviceHandle);
	if (!devpath) {
		perror(L"Failed to get device path\n");
		return EFI_NOT_FOUND;
	}
	Node = devpath;

	/* Traverse the device path to find HDD and USB */
	while (!IsDevicePathEnd(Node)) {
		if (DevicePathType(Node) == MEDIA_DEVICE_PATH &&
		    DevicePathSubType(Node) == MEDIA_HARDDRIVE_DP) {
			hdd = TRUE;
		} else if (DevicePathType(Node) == MESSAGING_DEVICE_PATH &&
			   DevicePathSubType(Node) == MSG_USB_DP) {
			usb = TRUE;
		}
		Node = NextDevicePathNode(Node);
	}

	/* This image is from the normal hard drive. Continue the booting
	 * process. */
	if (hdd == TRUE && usb == FALSE) {
		sv_verify = 1;
		return EFI_SUCCESS;
	}

	/* This image is from an installation media. Clear SVList */
	status = uefi_call_wrapper(RT->GetVariable, 5, L"SVList",
				   &shim_lock_guid, &attributes, &var_size,
				   (void *)&var);
	if (status == EFI_SUCCESS || status == EFI_BUFFER_TOO_SMALL) {
		status = uefi_call_wrapper(RT->SetVariable, 5, L"SVList",
					   &shim_lock_guid, attributes, 0,
					   NULL);
		if (status != EFI_SUCCESS)
			return status;
	}

	sv_verify = 0;

	return EFI_SUCCESS;
}
