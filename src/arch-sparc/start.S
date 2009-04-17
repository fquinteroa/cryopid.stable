/* _start stolen from dietlibc */
.global _start
_start:
	mov	%g0, %fp
	sub	%sp, 6*4, %sp
	ld	[%sp+22*4], %o0
	add	%sp, 23*4, %o1
	add	%o1, %o0, %o2
	add	%o2, %o0, %o2
	add	%o2, %o0, %o2
	add	%o2, %o0, %o2
	add	%o2, 4, %o2
	sethi	%hi(environ), %o3
	or	%o3, %lo(environ), %o3
	st	%o2, [%o3]
	call	main
	nop
	ret
