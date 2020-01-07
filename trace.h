#ifndef __TRACE_H__
#define __TRACE_H__

#include <stdio.h>
#include <stdint.h>

typedef	uint8_t			u8;
typedef	uint16_t		u16;
typedef	uint32_t		u32;
typedef	uint64_t		u64;

#define	TRACE_PROT_NONE		0x00
#define	TRACE_PROT_READ		0x01
#define	TRACE_PROT_WRITE	0x02
#define	TRACE_PROT_EXEC		0x04

#define	TRACE_MAP_SHARED	0x01
#define TRACE_MAP_PRIVATE	0x02
#define TRACE_MAP_FIXED		0x10
#define TRACE_MAP_ANONYMOUS	0x20

#define	TRACE_LITTLE_ENDIAN	0x00
#define	TRACE_BIG_ENDIAN	0x01
#define	TRACE_NO_VALUE		0x00
#define	TRACE_HAS_VALUE		0x02

#define	TRACE_TYPE_OTHER	0x00
#define	TRACE_TYPE_JCC		0x01
#define	TRACE_TYPE_JMP		0x02
#define	TRACE_TYPE_JMP_INDIRECT	0x03
#define	TRACE_TYPE_CALL		0x04
#define	TRACE_TYPE_RET		0x05
#define	TRACE_TYPE_RTI		0x07

typedef struct {
	/* variables */
	FILE*		file;
	void*		sys;
	int		endianess;

	/* callbacks */
	const char*	(*get_state)(void* sys, void* evt);
	const char*	(*get_insn)(void* sys, void* evt, unsigned int* len);
	const char**	(*get_assembly)(void* sys, void* evt, unsigned int* len, char* type);
	u64		(*get_pc)(void* sys, void* evt);
	u64		(*get_step)(void* sys, void* evt);
	u32		(*get_tid)(void* sys, void* evt);
} TRACE;

TRACE*	TRACEOpen(const char* filename);
void	TRACEClose(TRACE* trace);
void	TRACEStep(TRACE* trace, void* event);
void	TRACEMap(TRACE* trace, void* event, u64 addr, u64 len, int prot, int flags, u64 offset, u32 fd, u64 result, const char* filename);
void	TRACEUnmap(TRACE* trace, void* event, u64 addr, u64 len, u64 result);
void	TRACEWriteI8(TRACE* trace, void* event, u64 addr, u8 value);
void	TRACEWriteI16(TRACE* trace, void* event, u64 addr, u16 value);
void	TRACEWriteI32(TRACE* trace, void* event, u64 addr, u32 value);
void	TRACEWriteI64(TRACE* trace, void* event, u64 addr, u64 value);
void	TRACEReadI8(TRACE* trace, void* event, u64 addr, u8 value);
void	TRACEReadI16(TRACE* trace, void* event, u64 addr, u16 value);
void	TRACEReadI32(TRACE* trace, void* event, u64 addr, u32 value);
void	TRACEReadI64(TRACE* trace, void* event, u64 addr, u64 value);
void	TRACEReadI8Fault(TRACE* trace, void* event, u64 addr);
void	TRACEReadI16Fault(TRACE* trace, void* event, u64 addr);
void	TRACEReadI32Fault(TRACE* trace, void* event, u64 addr);
void	TRACEReadI64Fault(TRACE* trace, void* event, u64 addr);

#endif
