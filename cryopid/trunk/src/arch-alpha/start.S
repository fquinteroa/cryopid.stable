/* _start stolen from dietlibc */
.global _start
_start:
	clr	$fp		/* clear frame pointer */
	br	$gp,.Lstart	/* set global pointer */
.Lstart:
	ldgp	$gp, 0($gp)
	ldl	$16, 0($sp)	/* argc / a0 */
	lda	$17, 8($sp)	/* argv / a1 */
	addq	$16,   1, $18	/* argp / a2 */
	s8addq	$18, $17, $18	/* (8*(argc+1))+argv -> argp  */
	stq	$18, environ
	jsr	$26, main
