#ifndef _CPLAYOUT_H_
#define _CPLAYOUT_H_

#define TRAMPOLINES_START	0x001000

#define TRAMPOLINE_ADDR(x)	(TRAMPOLINES_START + (PAGE_SIZE*(1+(x))))

#define THREAD_COUNTER_ADDR	TRAMPOLINES_START   /* address of atomic_t */
#define THREAD_COUNTER		((atomic_t*)(THREAD_COUNTER_ADDR))

#define RESUMER_START	0x00000000 /* Lowest location resumer will be at */
#define RESUMER_END	0x00800000 /* Highest location resumer will be at */

#define TOP_OF_STACK	0x00800000

#define MALLOC_START	0x01000000 /* Here we store a pool of 32MB to use */
#define MALLOC_END	0x02000000

/* So with the above parameters, our memory map looks something like:
 *
 * RESUMER_START     code
 *                   data
 *
 *
 * TOP_OF_STACK      stack
 * RESUMER_END
 * TRAMPOLINE_ADDR
 *
 * MALLOC_START
 * MALLOC_END
 *
 * ... program stuff
 */

#endif /* _CPLAYOUT_H_ */
