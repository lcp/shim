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
 *
 * Significant portions of this code are derived from Tianocore
 * (http://tianocore.sf.net) and are Copyright 2009-2012 Intel
 * Corporation.
 */

#ifndef __SVLIST_H__
#define __SVLIST_H__

#include "PeImage.h"

typedef struct {
	UINT16 dv;
	UINT16 sv;
} __attribute__((packed)) svnode_t;

typedef struct {
	UINT32 size;
	UINT8 signer[4];
	svnode_t nodes[0];
} __attribute__((packed)) svlist_t;

static inline UINT32
count_nodes (const svlist_t *list)
{
	return (list->size - sizeof(svlist_t)) / sizeof(svnode_t);
}

EFI_STATUS check_security_version(const EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr);
EFI_STATUS check_boot_device(const EFI_HANDLE image_handle);
EFI_STATUS check_svlist_request();
EFI_STATUS mirror_svlist();

#endif /* __SVLIST_H__ */
