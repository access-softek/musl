#include "reloc.h"

#if __has_feature(ptrauth_intrinsics)

#include <stdint.h>

#define R_AARCH64_AUTH_ABS64    0x244
/* Define R_AARCH64_JUMP_SLOT manually to avoid including elf.h. */
#define R_AARCH64_JUMP_SLOT     0x402
#define R_AARCH64_AUTH_RELATIVE 0x411
#define R_AARCH64_AUTH_GLOB_DAT 0x412

#define DT_AARCH64_PAC_PLT      0x70000003
#define DT_AARCH64_AUTH_RELRSZ  0x70000011
#define DT_AARCH64_AUTH_RELR    0x70000012
#define DT_AARCH64_AUTH_RELRENT 0x70000013

static uint64_t do_sign_ia(uint64_t modifier, uint64_t value)
{
	__asm__ ("pacia %0, %1" : "+r" (value) : "r" (modifier));
	return value;
}

static uint64_t do_sign_ib(uint64_t modifier, uint64_t value)
{
	__asm__ ("pacib %0, %1" : "+r" (value) : "r" (modifier));
	return value;
}

static uint64_t do_sign_da(uint64_t modifier, uint64_t value)
{
	__asm__ ("pacda %0, %1" : "+r" (value) : "r" (modifier));
	return value;
}

static uint64_t do_sign_db(uint64_t modifier, uint64_t value)
{
	__asm__ ("pacdb %0, %1" : "+r" (value) : "r" (modifier));
	return value;
}

static int do_pauth_reloc(uint64_t* reladdr, uint64_t value)
{
	if (value == 0) {
		*reladdr = 0;
		return 1;
	}
	uint64_t schema = *reladdr;
	unsigned discrim = (schema >> 32) & 0xffff;
	int addr_div = schema >> 63;
	int key = (schema >> 60) & 0x3;
	uint64_t modifier = discrim;
	if (addr_div)
		modifier = (modifier << 48) | (uint64_t)reladdr;

	switch (key) {
		default:
			*reladdr = do_sign_ia(modifier, value);
			break;
		case 1:
			*reladdr = do_sign_ib(modifier, value);
			break;
		case 2:
			*reladdr = do_sign_da(modifier, value);
			break;
		case 3:
			*reladdr = do_sign_db(modifier, value);
			break;
	}
	return 1;
}

static int has_dyn_tag(uint64_t* dyn, uint64_t tag)
{
	while (*dyn) {
		if (*dyn == tag)
			return 1;
		dyn += 2;
	}
	return 0;
}

int do_target_reloc(int type, uint64_t* reladdr, uint64_t base,
                    uint64_t symval, uint64_t addend, int is_phase_2,
                    uint64_t* dyn, uint64_t error_sym)
{
	if (type == R_AARCH64_JUMP_SLOT && has_dyn_tag(dyn, DT_AARCH64_PAC_PLT)) {
		*reladdr = do_sign_ia((uint64_t)reladdr, *reladdr);
		return 1;
	}
	if (type == R_AARCH64_AUTH_GLOB_DAT) {
		/* We can't rely on is_phase_2 here, so check if the relocation slot is not filled.
		 * Check bits 0...47 against null:
		 * - before relocation is resolved, these are known to contain zeros:
		 *   - bits 0...31 store addend which is known to be zero for GOT slots;
		 *   - bits 32...47 store discriminator which is known to be zero for GOT slots;
		 * - after relocation is resolved to a non-undef symbol, these would contain
		 *   non-null value since typically virtual address width is 48 bits or lower.
		 * We cannot check the whole slot contents against null since before the relocation is
		 * resolved, bits 60...63 contain signing scheme (key value and address diversity flag).
		 *
		 * See:
		 * - https://github.com/ARM-software/abi-aa/blob/2025Q1/pauthabielf64/pauthabielf64.rst#encoding-the-signing-schema
		 * - https://github.com/ARM-software/abi-aa/blob/2025Q1/pauthabielf64/pauthabielf64.rst#default-signing-schema */
		if ((*reladdr & 0xffffffffffffull) == 0)
			return do_pauth_reloc(reladdr, symval + addend);
		return 1;
	}
	/* We don't process auth relocs until we load all dependencies */
	if (is_phase_2)
		return 1;
	/* NOTE: we have to rely on this hack since we set error = error_impl in __dls3 manually. */
	if (*reladdr == error_sym)
		return 1;
	switch (type)
	{
		case R_AARCH64_AUTH_ABS64:
			return do_pauth_reloc(reladdr, symval + addend);
		case R_AARCH64_AUTH_RELATIVE:
			return do_pauth_reloc(reladdr, base + addend);
		default:
			return 0;
	}
}

static uint64_t dyn_value(uint64_t* dyn, uint64_t tag)
{
	while (*dyn)
	{
		if (*dyn == tag)
			return dyn[1];
		else
			dyn += 2;
	}
	return 0;
}

void do_pauth_relr(uint64_t base, uint64_t* dyn)
{
	uint64_t* relr = (uint64_t*)dyn_value(dyn, DT_AARCH64_AUTH_RELR);
	if (relr == 0)
		return;
	uint64_t relr_size = dyn_value(dyn, DT_AARCH64_AUTH_RELRSZ);
	uint64_t relr_ent = dyn_value(dyn, DT_AARCH64_AUTH_RELRENT);
	if (relr_ent != sizeof(uint64_t))
		return;
	uint64_t *reloc_addr;
	for (; relr_size; relr++, relr_size-=relr_ent) {
		if ((relr[0]&1) == 0) {
			reloc_addr = (uint64_t*)(base + relr[0]);
			do_pauth_reloc(reloc_addr, base + (*reloc_addr & 0xffffffff));
			reloc_addr++;
		} else {
			int i = 0;
			for (uint64_t bitmap=relr[0]; (bitmap>>=1); ++i)
				if (bitmap&1) {
					uint64_t val = base + (reloc_addr[i] & 0xffffffff);
					do_pauth_reloc(&reloc_addr[i], val);
				}
			reloc_addr += 8*sizeof(uint64_t)-1;
		}
	}
}

#endif
