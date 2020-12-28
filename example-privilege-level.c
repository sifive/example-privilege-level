/* Copyright 2020 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>

#include <metal/cpu.h>
#include <metal/csr.h>
#include <metal/pmp.h>
#include <metal/privilege.h>

#include <metal/drivers/riscv_cpu.h>

#define EXTRACT_FIELD(val, which) \
	(((val) & (which)) / ((which) & ~((which)-1)))

#define INSERT_FIELD(val, which, fieldval) \
	(((val) & ~(which)) | ((fieldval) * ((which) & ~((which)-1))))

// TODO: Currently, METAL_R9_EXCEPTION_CODE is reserved in freedom-metal
#define METAL_ECALL_S_EXCEPTION_CODE	METAL_R9_EXCEPTION_CODE

/* Create a stack for user-mode execution */
uint8_t s_stack[768] __attribute__((aligned(16)));
uint8_t u_stack[768] __attribute__((aligned(16)));

/* Create the register file for user mode execution */
struct metal_register_file s_regfile = {
	.sp = (uintptr_t) (s_stack + sizeof(s_stack)),
};

struct metal_register_file u_regfile = {
	.sp = (uintptr_t) (u_stack + sizeof(u_stack)),
};

/* TODO: Currently, metal_privilege_drop_to_mode only support M-mode */
#define METAL_SSTATUS_SPP	0x00000100UL
#define METAL_SSTATUS_SPIE	0x00000020UL

static void switch_mode(enum metal_privilege_mode next_mode,
			struct metal_register_file regfile,
			metal_privilege_entry_point_t next_addr)
{
	uintptr_t value;
	register uintptr_t ra __asm__("ra") __attribute__((__unused__));
	register uintptr_t sp __asm__("sp") __attribute__((__unused__));

	METAL_CPU_GET_CSR(sstatus, value);

	/* Set SPP to the requested privilege mode */
	value = INSERT_FIELD(value, METAL_SSTATUS_SPP, next_mode);

	/* Set SPIE bits by clearing value */
	value = INSERT_FIELD(value, METAL_SSTATUS_SPIE, 0);

	METAL_CPU_SET_CSR(sstatus, value);

	/* Set the entry point in SEPC */
	METAL_CPU_SET_CSR(sepc, next_addr);

	/* Set the register file */
	ra = regfile.ra;
	sp = regfile.sp;

	__asm__ __volatile__("sret");
}

static void supervisor_mode_trap_handler(struct metal_cpu *cpu, int cause)
{
	uintptr_t epc = metal_cpu_get_exception_pc(cpu);
	int inst_len = metal_cpu_get_instruction_length(cpu, epc);
	uintptr_t value;

	if (cause == METAL_ECALL_S_EXCEPTION_CODE) {
		printf("Caught ecall from supervisor mode\n");
		METAL_CPU_GET_CSR(mstatus, value);
		value = EXTRACT_FIELD(value, METAL_MSTATUS_MPP);
		printf("mstatus.MPP is 0x%x\n", (unsigned int)value);
		metal_cpu_set_exception_pc(cpu, epc + inst_len);
	} else {
		exit(7);
	}
}

static void user_mode_trap_handler(struct metal_cpu *cpu, int cause)
{
	uintptr_t epc = metal_cpu_get_exception_pc(cpu);
	int inst_len = metal_cpu_get_instruction_length(cpu, epc);
	uintptr_t value;

	if (cause == METAL_ECALL_U_EXCEPTION_CODE) {
		printf("Caught ecall from user mode\n");
		METAL_CPU_GET_CSR(mstatus, value);
		value = EXTRACT_FIELD(value, METAL_MSTATUS_MPP);
		printf("mstatus.MPP is 0x%x\n", (unsigned int)value);
		metal_cpu_set_exception_pc(cpu, epc + inst_len);
	} else {
		exit(8);
	}
}

static void supervisor_mode_entry_point(void)
{
	/* Perform a syscall in supervisor mode */
	__asm__ volatile("ecall");

	return;
}

static void user_mode_entry_point(void)
{
	/* Perform a syscall in user mode */
	__asm__ volatile("ecall");

	return;
}

static inline void machine_mode_test(void)
{
	uintptr_t value;

	METAL_CPU_GET_CSR(mstatus, value);
	value = EXTRACT_FIELD(value, METAL_MSTATUS_MPP);
	printf("mstatus.MPP is 0x%x\n", (unsigned int)value);
}

int main(void)
{
	int ret;
	struct metal_cpu *cpu;
	struct metal_interrupt *cpu_intr;
#ifdef __METAL_DT_PMP_HANDLE
	struct metal_pmp *pmp;
#endif

	/* Initialize interrupt handling */
	cpu = metal_cpu_get(metal_cpu_get_current_hartid());
	if (!cpu) {
		printf("Unable to get CPU handle\n");
		return 1;
	}

	cpu_intr = metal_cpu_interrupt_controller(cpu);
	if (!cpu_intr) {
		printf("Unable to get CPU Interrupt handle\n");
		return 2;
	}

	metal_interrupt_init(cpu_intr);

	/* Register our own handler for traps */
	ret = metal_cpu_exception_register(cpu,
					   METAL_ECALL_S_EXCEPTION_CODE,
					   supervisor_mode_trap_handler);
	if (ret < 0) {
		printf("Failed to register S-Mode exception handler\n");
		return 3;
	}

	ret = metal_cpu_exception_register(cpu,
					   METAL_ECALL_U_EXCEPTION_CODE,
					   user_mode_trap_handler);
	if (ret < 0) {
		printf("Failed to register U-Mode exception handler\n");
		return 4;
	}

#ifdef __METAL_DT_PMP_HANDLE
	/* Initialize PMPs */
	pmp = metal_pmp_get_device();
	if (!pmp) {
		printf("Unable to get PMP Device\n");
		return 5;
	}
	metal_pmp_init(pmp);

	/* Configure PMP 0 to allow access to all memory */
	struct metal_pmp_config config = {
		.L = METAL_PMP_UNLOCKED,
		.A = METAL_PMP_TOR,
		.X = 1,
		.W = 1,
		.R = 1,
	};
	ret = metal_pmp_set_region(pmp, 0, config, -1);
	if (ret != 0) {
		return 6;
	}
#endif
	/* We are in machine mode at the beginning */
	printf("=== In machine mode at the beginning ===\n");
	machine_mode_test();

	/* Transfer to supervisor mode */
	printf("=== Transfer privilege to supervisor mode ===\n");

	s_regfile.ra = (metal_xreg_t)&&go_umode;
	/* Use API of freedom-metal to switch mode */
	metal_privilege_drop_to_mode(METAL_PRIVILEGE_SUPERVISOR,
				     s_regfile,
				     supervisor_mode_entry_point);
go_umode:
	/* Transfer to user mode */
	printf("=== Transfer privilege to user mode ===\n");

	u_regfile.ra = (metal_xreg_t)&&go_exit;
	/* Use our own function to switch mode */
	switch_mode(METAL_PRIVILEGE_USER,
		    u_regfile,
		    user_mode_entry_point);

go_exit:
	return 0;
}
