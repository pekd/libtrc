#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "trace.h"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define	U16B(x)		(x)
#define	U32B(x)		(x)
#define	U64B(x)		(x)
#define	U16L(x)		__builtin_bswap16(x)
#define	U32L(x)		__builtin_bswap32(x)
#define	U64L(x)		__builtin_bswap64(x)
#else
#define	U16B(x)		__builtin_bswap16(x)
#define	U32B(x)		__builtin_bswap32(x)
#define	U64B(x)		__builtin_bswap64(x)
#define	U16L(x)		(x)
#define	U32L(x)		(x)
#define	U64L(x)		(x)
#endif


static const char MAGIC[6] = { 'X', 'T', 'R', 'C', 0, 0 };

typedef struct {
	u32	magic;
	u32	tid;
	u64	step;
	u64	pc;
} STEP;

typedef struct {
	u32	magic;
	u32	tid;
	u64	addr;
	u64	len;
	u64	off;
	u64	result;
	u32	prot;
	u32	flags;
	u32	fd;
	u16	filename;
} MMAPEVT;

typedef struct {
	u32	magic;
	u32	tid;
	u64	addr;
	u64	len;
	u32	result;
} MUNMAPEVT;

typedef struct {
	u32	magic;
	u32	tid;
	u64	addr;
	u64	value;
	u8	size;
	u8	flags;
} MEMEVT;

static const char* nothing = "";

static const char* default_get_state(void* sys, void* evt)
{
	return nothing;
}

static const char* default_get_insn(void* sys, void* evt, unsigned int* len)
{
	*len = 0;
	return nothing;
}

static const char** default_get_assembly(void* sys, void* evt, unsigned int* len, char* type)
{
	*len = 0;
	*type = 0;
	return &nothing;
}

static u64 default_zero_u64(void* sys, void* evt)
{
	return 0;
}

static u32 default_zero_u32(void* sys, void* evt)
{
	return 0;
}

TRACE* TRACEOpen(const char* filename)
{
	TRACE* trace = (TRACE*) malloc(sizeof(TRACE));
	if(!trace)
		return NULL;

	/* open file and write magic */
	trace->file = fopen(filename, "wb");
	if(!trace->file) {
		free(trace);
		return NULL;
	}

	if(fwrite(MAGIC, sizeof(MAGIC), 1, trace->file) != 1) {
		int tmp = errno;
		fclose(trace->file);
		free(trace);
		errno = tmp;
		return NULL;
	}

	/* clear sys */
	trace->sys = NULL;

	/* set default endianess */
	trace->endianess = TRACE_LITTLE_ENDIAN;

	/* set callbacks */
	trace->get_state = default_get_state;
	trace->get_insn = default_get_insn;
	trace->get_assembly = default_get_assembly;
	trace->get_pc = default_zero_u64;
	trace->get_step = default_zero_u64;
	trace->get_tid = default_zero_u32;

	return trace;
}

void TRACEClose(TRACE* trace)
{
	fclose(trace->file);
	free(trace);
}

void TRACEStep(TRACE* trace, void* evt)
{
	STEP step = { 0 };
	char type = 0;
	u16 statelen;
	u16 insncnt;
	u32 instlen;
	unsigned int insn_count;
	unsigned int inst_len;
	unsigned int i;

	const char* state = trace->get_state(trace->sys, evt);
	const char* instdata = trace->get_insn(trace->sys, evt, &inst_len);
	const char** assembly = trace->get_assembly(trace->sys, evt, &insn_count, &type);

	insncnt = U16B(insn_count);
	instlen = U32B(inst_len);
	statelen = U16B(strlen(state));

	memcpy(&step.magic, "STEP", 4);
	step.tid = U32B(trace->get_tid(trace->sys, evt));
	step.step = U64B(trace->get_step(trace->sys, evt));
	step.pc = U64B(trace->get_pc(trace->sys, evt));
	fwrite(&step, sizeof(step), 1, trace->file);
	fwrite(&statelen, 2, 1, trace->file);
	fwrite(state, strlen(state), 1, trace->file);
	fwrite(&instlen, 4, 1, trace->file);
	fwrite(instdata, inst_len, 1, trace->file);
	fwrite(&type, 1, 1, trace->file);
	fwrite(&insncnt, 2, 1, trace->file);
	for(i = 0; i < insn_count; i++) {
		const char* insn = assembly[i];
		u16 insnlen = U16B(strlen(insn));
		fwrite(&insnlen, 2, 1, trace->file);
		fwrite(insn, strlen(insn), 1, trace->file);
	}
}

void TRACEMap(TRACE* trace, void* event, u64 addr, u64 len, int prot, int flags, u64 offset, u32 fd, u64 result, const char* filename)
{
	MMAPEVT evt = { 0 };
	memcpy(&evt.magic, "MMAP", 4);
	evt.addr = U64B(addr);
	evt.len = U64B(len);
	evt.prot = U32B(prot);
	evt.flags = U32B(flags);
	evt.off = U64B(offset);
	evt.fd = U32B(fd);
	evt.result = U64B(result);

	if(filename) {
		evt.filename = U16B(strlen(filename));
		fwrite(&evt, 54, 1, trace->file);
		fwrite(filename, strlen(filename), 1, trace->file);
	} else {
		fwrite(&evt, 54, 1, trace->file);
	}
}

void TRACEUnmap(TRACE* trace, void* event, u64 addr, u64 len, u64 result)
{
	MUNMAPEVT evt = { 0 };
	memcpy(&evt.magic, "UMAP", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.len = U64B(len);
	evt.result = U32B(len);
	fwrite(&evt, 28, 1, trace->file);
}

void TRACEWriteI8(TRACE* trace, void* event, u64 addr, u8 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMW", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 1;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEWriteI16(TRACE* trace, void* event, u64 addr, u16 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMW", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 2;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEWriteI32(TRACE* trace, void* event, u64 addr, u32 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMW", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 4;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEWriteI64(TRACE* trace, void* event, u64 addr, u64 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMW", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 8;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI8(TRACE* trace, void* event, u64 addr, u8 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 1;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI16(TRACE* trace, void* event, u64 addr, u16 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 2;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI32(TRACE* trace, void* event, u64 addr, u32 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 4;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI64(TRACE* trace, void* event, u64 addr, u64 value)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = U64B(value);
	evt.size = 8;
	evt.flags = TRACE_HAS_VALUE | trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI8Fault(TRACE* trace, void* event, u64 addr)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = 0;
	evt.size = 1;
	evt.flags = trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI16Fault(TRACE* trace, void* event, u64 addr)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = 0;
	evt.size = 2;
	evt.flags = trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI32Fault(TRACE* trace, void* event, u64 addr)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = 0;
	evt.size = 4;
	evt.flags = trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}

void TRACEReadI64Fault(TRACE* trace, void* event, u64 addr)
{
	MEMEVT evt = { 0 };
	memcpy(&evt.magic, "MEMR", 4);
	evt.tid = U32B(trace->get_tid(trace->sys, event));
	evt.addr = U64B(addr);
	evt.value = 0;
	evt.size = 8;
	evt.flags = trace->endianess;
	fwrite(&evt, 26, 1, trace->file);
}
