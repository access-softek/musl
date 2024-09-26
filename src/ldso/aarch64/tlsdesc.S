// size_t __tlsdesc_static(size_t *a)
// {
// 	return a[1];
// }
.global __tlsdesc_static
.hidden __tlsdesc_static
.type __tlsdesc_static,@function
__tlsdesc_static:
#if __has_feature(ptrauth_elf_got)
	add   x17,x0,8
	ldr   x16,[x17]
	autda x16,x17
	mov   x17,x16
	xpacd x17
	cmp   x16,x17
	b.eq  .Lauth_success_0
	brk   #0xc472
.Lauth_success_0:
	mov   x0,x16
#else
	ldr x0,[x0,#8]
#endif
	ret

// size_t __tlsdesc_dynamic(size_t *a)
// {
// 	struct {size_t modidx,off;} *p = (void*)a[1];
// 	size_t *dtv = *(size_t**)(tp - 8);
// 	return dtv[p->modidx] + p->off - tp;
// }
.global __tlsdesc_dynamic
.hidden __tlsdesc_dynamic
.type __tlsdesc_dynamic,@function
__tlsdesc_dynamic:
	stp x1,x2,[sp,#-16]!
	mrs x1,tpidr_el0      // tp
#if __has_feature(ptrauth_elf_got)
	add   x17,x0,8
	ldr   x16,[x17]
	autda x16,x17
	mov   x17,x16
	xpacd x17
	cmp   x16,x17
	b.eq  .Lauth_success_1
	brk   #0xc472
.Lauth_success_1:
	mov   x0,x16
#else
	ldr x0,[x0,#8]        // p
#endif
	ldp x0,x2,[x0]        // p->modidx, p->off
	sub x2,x2,x1          // p->off - tp
	ldr x1,[x1,#-8]       // dtv
	ldr x1,[x1,x0,lsl #3] // dtv[p->modidx]
	add x0,x1,x2          // dtv[p->modidx] + p->off - tp
	ldp x1,x2,[sp],#16
	ret

.global __tlsdesc_undef_weak
.hidden __tlsdesc_undef_weak
.type __tlsdesc_undef_weak,@function
__tlsdesc_undef_weak:
	mov x0, #0
	mrs x8, TPIDR_EL0
	sub x0, x0, x8
	ret
