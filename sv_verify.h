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

#ifndef __SV_VERIFY_H__
#define __SV_VERIFY_H__

#define SIGNER_MAX_SIZE 26	/* The maximum signer length, including the
				 * ending NULL character */
#define SVLIST_MAGIC 0x72655653 /* "SVer" */

typedef struct {
	UINT32 dv;
	UINT16 sv;
	UINT8  padding[2];
} __attribute__((packed)) svnode_t;

typedef struct {
	UINT32 magic;
	UINT16 size;
	CHAR8  signer[SIGNER_MAX_SIZE];
	svnode_t nodes[0];
} __attribute__((packed)) svlist_t;

static inline UINT32
count_nodes (const svlist_t *list)
{
	return (list->size - sizeof(svlist_t)) / sizeof(svnode_t);
}

EFI_STATUS check_security_version(void *buffer, const UINT32 size);
EFI_STATUS check_boot_device(const EFI_HANDLE image_handle);
EFI_STATUS check_svlist_request();

#endif /* __SV_VERIFY_H__ */
