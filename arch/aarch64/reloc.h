#if __BYTE_ORDER == __BIG_ENDIAN
#define ENDIAN_SUFFIX "_be"
#else
#define ENDIAN_SUFFIX ""
#endif

#define LDSO_ARCH "aarch64" ENDIAN_SUFFIX

#define NO_LEGACY_INITFINI

#define TPOFF_K 0

#define REL_SYMBOLIC    R_AARCH64_ABS64
#define REL_GOT         R_AARCH64_GLOB_DAT
#define REL_PLT         R_AARCH64_JUMP_SLOT
#define REL_RELATIVE    R_AARCH64_RELATIVE
#define REL_COPY        R_AARCH64_COPY
#define REL_DTPMOD      R_AARCH64_TLS_DTPMOD64
#define REL_DTPOFF      R_AARCH64_TLS_DTPREL64
#define REL_TPOFF       R_AARCH64_TLS_TPREL64

#if __has_feature(ptrauth_elf_got)
#define R_AARCH64_AUTH_TLSDESC 0xe202
#define REL_TLSDESC     R_AARCH64_AUTH_TLSDESC
#else
#define REL_TLSDESC     R_AARCH64_TLSDESC
#endif

#define CRTJMP(pc,sp) __asm__ __volatile__( \
	"mov sp,%1 ; br %0" : : "r"(pc), "r"(sp) : "memory" )

#if __has_feature(ptrauth_calls)
#define TARGET_RELOCATE(dso, type, reladdr, sym, addend, is_phase_2, dyn, error_sym) \
  do_target_reloc(dso, type, reladdr, sym, addend, is_phase_2, dyn, error_sym)
#define DO_TARGET_RELR(dso, dyn) do_pauth_relr(dso, dyn)

int do_target_reloc(int type, uint64_t* reladdr, uint64_t base, uint64_t symval,
                    uint64_t addend, int is_phase_2, uint64_t* dyn, uint64_t error_sym);

void do_pauth_relr(uint64_t base, uint64_t* dyn);

#define GETFUNCSYM(fp, sym, got) do { \
	hidden void sym(); \
	*(fp) = sym; } while(0)

#define FPTR_CAST(fty, p) \
  ((fty)__builtin_ptrauth_sign_unauthenticated((void*)(p), 0, 0))

#endif
