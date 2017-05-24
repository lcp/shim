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

#ifndef __BZIMAGE_H__
#define __BZIMAGE_H__

/* The header of the Linux bzImage */
struct setup_header {
	UINT8    setup_sects;
	UINT16   root_flags;
	UINT32   syssize;
	UINT16   ram_size;
	UINT16   vid_mode;
	UINT16   root_dev;
	UINT16   boot_flag;
	UINT16   jump;
	UINT32   header;
	UINT16   version;
	UINT32   realmode_swtch;
	UINT16   start_sys;
	UINT16   kernel_version;
	UINT8    type_of_loader;
	UINT8    loadflags;
	UINT16   setup_move_size;
	UINT32   code32_start;
	UINT32   ramdisk_image;
	UINT32   ramdisk_size;
	UINT32   bootsect_kludge;
	UINT16   heap_end_ptr;
	UINT8    ext_loader_ver;
	UINT8    ext_loader_type;
	UINT32   cmd_line_ptr;
	UINT32   initrd_addr_max;
	UINT32   kernel_alignment;
	UINT8    relocatable_kernel;
	UINT8    min_alignment;
	UINT16   xloadflags;
	UINT32   cmdline_size;
	UINT32   hardware_subarch;
	UINT64   hardware_subarch_data;
	UINT32   payload_offset;
	UINT32   payload_length;
	UINT64   setup_data;
	UINT64   pref_address;
	UINT32   init_size;
	UINT32   handover_offset;
	UINT16   secdata_offset;
} __attribute__((packed));

/* The struct for the secdata section */
struct sec_hdr {
	UINT16   hdr_length;
	UINT32   distro_version;
	UINT16   security_version;
} __attribute__((packed));

#endif
