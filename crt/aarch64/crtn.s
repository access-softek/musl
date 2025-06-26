.section .init
	ldp x29,x30,[sp],#16
	autiasp
	ret

.section .fini
	ldp x29,x30,[sp],#16
	autiasp
	ret
