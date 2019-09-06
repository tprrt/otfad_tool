/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "compute_crc32.h"

uint32_t compute_crc32(unsigned char *in, uint32_t size)
{
	uint32_t crc = 0xffffffff;
	uint32_t crc_tbl_lookup = 0;

	while (size--)
	{
		unsigned char c = *in++ & 0xff;
		crc_tbl_lookup = CRCTable[(crc >> 24) ^ c];
		crc = ((crc << 8) ^ (crc_tbl_lookup & 0xFFFFFF00)) | (crc_tbl_lookup & 0xFF);
	}

	return crc;
}