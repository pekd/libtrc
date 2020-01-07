#include <stdio.h>
#include "trace.h"

/* demo */
const char* get_state(void* sys, void* evt)
{
	return "step\n";
}

char insn[1] = { 42 };
const char* get_insn(void* sys, void* evt, unsigned int* len)
{
	*len = 1;
	insn[0] = (char) (uintptr_t) evt;
	return insn;
}

char buf[16];
const char* insnptr[3] = { "insn", "arg1", buf };
const char** get_assembly(void* sys, void* evt, unsigned int* len, char* type)
{
	*type = TRACE_TYPE_OTHER;
	*len = 3;
	sprintf(buf, "%d", (int) (uintptr_t) evt);
	return insnptr;
}

u64 get_pc(void* sys, void* evt)
{
	return (u64) evt;
}

u64 step = 0;
u64 get_step(void* sys, void* evt)
{
	return step++;
}

int main(void)
{
	TRACE* trace = TRACEOpen("demo.trc");
	if(!trace) {
		printf("Error: cannot open trace\n");
		return 1;
	}

	trace->get_state = get_state;
	trace->get_insn = get_insn;
	trace->get_assembly = get_assembly;
	trace->get_pc = get_pc;
	trace->get_step = get_step;
	trace->endianess = TRACE_BIG_ENDIAN;

	/* map two memory pages ... */
	TRACEMap(trace, (void*) 0, 0, 4096, TRACE_PROT_READ, TRACE_MAP_PRIVATE|TRACE_MAP_ANONYMOUS|TRACE_MAP_FIXED, 0, 0, 0, NULL);
	TRACEMap(trace, (void*) 0, 4096, 4096, TRACE_PROT_READ|TRACE_PROT_WRITE, TRACE_MAP_PRIVATE|TRACE_MAP_ANONYMOUS, 0, 0, 4096, "data");

	TRACEStep(trace, (void*) 0);

	TRACEStep(trace, (void*) 1);

	TRACEStep(trace, (void*) 2);
	TRACEWriteI32(trace, (void*) 2, 42, 0x4E6F6F64);
	TRACEWriteI16(trace, (void*) 2, 46, 0x6C65);

	TRACEStep(trace, (void*) 3);

	TRACEStep(trace, (void*) 4);

	TRACEStep(trace, (void*) 5);

	TRACEStep(trace, (void*) 6);

	TRACEStep(trace, (void*) 7);
	TRACEReadI8(trace, (void*) 7, 44, 0x6F);

	TRACEStep(trace, (void*) 8);
	TRACEUnmap(trace, (void*) 8, 0, 8192, 0);

	TRACEStep(trace, (void*) 9);

	TRACEClose(trace);
}

