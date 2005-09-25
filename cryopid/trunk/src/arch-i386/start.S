/* _start stolen from uclibc */
.global _start
_start:
	pop    %ecx
	mov    %esp,%ebx
	mov    %esp,%eax
	mov    %ecx,%edx
	lea    0x4(%eax,%edx,4),%eax
	xor    %ebp,%ebp
	push   %ebp
	push   %ebp
	push   %ebp
	mov    %esp,%ebp
	push   %eax
	push   %ebx
	push   %ecx
	call   main

