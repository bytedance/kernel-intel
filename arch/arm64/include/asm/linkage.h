#ifndef __ASM_LINKAGE_H
#define __ASM_LINKAGE_H

#define __ALIGN		.align 2
#define __ALIGN_STR	".align 2"

/*
 * Annotate a function as position independent, i.e., safe to be called before
 * the kernel virtual mapping is activated.
 */
#define SYM_FUNC_START_PI(x)			\
		SYM_FUNC_START_ALIAS(__pi_##x);	\
		SYM_FUNC_START(x)

#define SYM_FUNC_START_WEAK_PI(x)		\
		SYM_FUNC_START_ALIAS(__pi_##x);	\
		SYM_FUNC_START_WEAK(x)

#define SYM_FUNC_END_PI(x)			\
		SYM_FUNC_END(x);		\
		SYM_FUNC_END_ALIAS(__pi_##x)

/*
 * Annotate sym code that only executed by user space
 */
#define SYM_CODE_START_USER(name)			\
	SYM_CODE_START(name)

#define SYM_CODE_END_USER(name)			\
	SYM_END(name, SYM_T_NONE)

/*
 * Record the address range of each SYM_CODE function in a struct code_range
 * in a special section.
 */
#define SYM_CODE_END(name)				\
	SYM_END(name, SYM_T_NONE)			;\
99:	.pushsection "sym_code_functions", "aw"		;\
	.quad	name					;\
	.quad	99b					;\
	.popsection
#endif
