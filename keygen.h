#ifndef KEYGEN_H
#define KEYGEN_H

#define EFI_HIBERNATE_GUID \
	{ 0xfe141863, 0xc070, 0x478e, {0xb8, 0xa3, 0x87, 0x8a, 0x5d, 0xc9, 0xef, 0x21} }

EFI_STATUS setup_rand (void);
EFI_STATUS generate_new_keys (const int bits, const int days);
EFI_STATUS copy_certs (void);

#endif
