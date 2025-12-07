// Version 0.3.1 Code by Cyril "Parad0x141" Bouvier - 2025


// Based on various public resources and personal knowledge of x64 assembly,
// this header only library provide a way to bypass the lack of inline assembly
// in x64 MSVC builds by generating shellcode at runtime :)).


// For now error handling is reeeaaallly minimal.
// Will improve that later, but for now, NO OVERFLOW CHECKS, NO (very fews) VALIDATIONS, NO SHELLCODE ANALYSIS,NO DEBUGGING TOOLS.
// Better know what you are doing when using it, you have been warned :))

// NO SSE/AVX instructions for now. Might be added later.

// Feel free to extend, use, abuse, modify, copy, share, etc this code as you wish.

// Note that some high level func are broken atm, this lib is a WIP.

/*
 * MICROSOFT X64 CALLING CONVENTION
 * ================================
 * Arguments: RCX, RDX, R8, R9, then stack (right-to-left)
 * Return:    RAX (integers), XMM0 (floats)
 *
 * Volatile:     RAX, RCX, RDX, R8-R11, XMM0-XMM5
 * Non-volatile: RBX, RBP, RDI, RSI, RSP, R12-R15, XMM6-XMM15
 *
 * Stack:
 *   - Must be 16-byte aligned before CALL (RSP % 16 == 8)
 *   - Caller must allocate 32 bytes shadow space for callee
 *   - Callee can use shadow space to spill registers
 */

#pragma once

#include <vector>
#include <optional>
#include <array>
#include <chrono>
#include <random>
#include <cassert>


/// <summary>
/// X64 Runtime Assembler - Generate shellcode dynamically
/// Supports common x64 instructions & provide a simple API to work with assembly at runtime.
/// </summary>
class X64Assembler {
private:
	std::vector<uint8_t> code;

	void Emit(uint8_t byte) 
	{
		code.push_back(byte);
	}

	void EmitWord(uint16_t word)
	{
		Emit(word & 0xFF);
		Emit((word >> 8) & 0xFF);
	}

	void EmitDword(uint32_t dword)
	{
		Emit(dword & 0xFF);
		Emit((dword >> 8) & 0xFF);
		Emit((dword >> 16) & 0xFF);
		Emit((dword >> 24) & 0xFF);
	}

	void EmitQword(uint64_t qword)
	{
		EmitDword(qword & 0xFFFFFFFF);
		EmitDword((qword >> 32) & 0xFFFFFFFF);
	}

	static uint8_t RandomReg()              // 0 = RAX ... 15 = R15
	{
		static std::mt19937_64 rng{ std::random_device{}() };
		return static_cast<uint8_t>(rng() & 0xF);
	}

	static void EmitRandomNop(std::vector<uint8_t>& dst)
	{
		static const std::array<std::vector<uint8_t>, 7> nop_pool = {
			std::vector<uint8_t>{0x90},                                // 1 byte
			std::vector<uint8_t>{0x0F, 0x1F, 0x00},                   // 3
			std::vector<uint8_t>{0x0F, 0x1F, 0x40, 0x00},             // 4
			std::vector<uint8_t>{0x0F, 0x1F, 0x44, 0x00, 0x00},       // 5
			std::vector<uint8_t>{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, // 6
			std::vector<uint8_t>{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}, // 7
			std::vector<uint8_t>{0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00} // 8
		};
		static std::mt19937_64 rng{ std::random_device{}() };
		const auto& nop = nop_pool[rng() % nop_pool.size()];
		dst.insert(dst.end(), nop.begin(), nop.end());
	}

	static bool EmitRandomNopV2(std::vector<uint8_t>& code, size_t maxRemaining) 
	{
		static std::mt19937 rng{ std::random_device{}() };


		static const std::array<std::vector<uint8_t>, 8> nop_pool = {
			std::vector<uint8_t>{0x90},                                    // 1 byte
			std::vector<uint8_t>{0x66, 0x90},                             // 2 bytes  
			std::vector<uint8_t>{0x0F, 0x1F, 0x00},                       // 3 bytes
			std::vector<uint8_t>{0x0F, 0x1F, 0x40, 0x00},                 // 4 bytes
			std::vector<uint8_t>{0x0F, 0x1F, 0x44, 0x00, 0x00},           // 5 bytes
			std::vector<uint8_t>{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},     // 6 bytes
			std::vector<uint8_t>{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}, // 7 bytes
			std::vector<uint8_t>{0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00} // 8 bytes
		};

		std::vector<const std::vector<uint8_t>*> available_nops;
		for (const auto& nop : nop_pool)
		{
			if (nop.size() <= maxRemaining)
			{
				available_nops.push_back(&nop);
			}
		}

		if (available_nops.empty()) 
		{
			return false; 
		}

		const auto& selected_nop = *available_nops[rng() % available_nops.size()];
		code.insert(code.end(), selected_nop.begin(), selected_nop.end());

		return true;
	}

public:
	X64Assembler() = default;

	// ============================================================
	// MOV Instructions - Register to Immediate
	// ============================================================

	/// <summary>MOV RAX, imm64 (48 B8 + 8 bytes)</summary>
	void MovRax(uint64_t imm64)
	{
		Emit(0x48); // REX.W
		Emit(0xB8); // MOV RAX
		EmitQword(imm64);
	}

	/// <summary>MOV RCX, imm64 (48 B9 + 8 bytes)</summary>
	void MovRcx(uint64_t imm64)
	{
		Emit(0x48);
		Emit(0xB9);
		EmitQword(imm64);
	}

	/// <summary>MOV RDX, imm64 (48 BA + 8 bytes)</summary>
	void MovRdx(uint64_t imm64) 
	{
		Emit(0x48);
		Emit(0xBA);
		EmitQword(imm64);
	}

	/// <summary>MOV RBX, imm64 (48 BB + 8 bytes)</summary>
	void MovRbx(uint64_t imm64)
	{
		Emit(0x48);
		Emit(0xBB);
		EmitQword(imm64);
	}

	/// <summary>MOV RSP, imm64 (48 BC + 8 bytes)</summary>
	void MovRsp(uint64_t imm64) 
	{
		Emit(0x48);
		Emit(0xBC);
		EmitQword(imm64);
	}

	/// <summary>MOV RBP, imm64 (48 BD + 8 bytes)</summary>
	void MovRbp(uint64_t imm64) 
	{
		Emit(0x48);
		Emit(0xBD);
		EmitQword(imm64);
	}

	/// <summary>MOV RSI, imm64 (48 BE + 8 bytes)</summary>
	void MovRsi(uint64_t imm64) 
	{
		Emit(0x48);
		Emit(0xBE);
		EmitQword(imm64);
	}

	/// <summary>MOV RDI, imm64 (48 BF + 8 bytes)</summary>
	void MovRdi(uint64_t imm64) 
	{
		Emit(0x48);
		Emit(0xBF);
		EmitQword(imm64);
	}

	/// <summary>MOV R8, imm64 (49 B8 + 8 bytes)</summary>
	void MovR8(uint64_t imm64)
	{
		Emit(0x49);
		Emit(0xB8);
		EmitQword(imm64);
	}

	/// <summary>MOV R9, imm64 (49 B9 + 8 bytes)</summary>
	void MovR9(uint64_t imm64)
	{
		Emit(0x49);
		Emit(0xB9);
		EmitQword(imm64);
	}

	/// <summary>MOV R10, imm64 (49 BA + 8 bytes)</summary>
	void MovR10(uint64_t imm64)
	{
		Emit(0x49);
		Emit(0xBA);
		EmitQword(imm64);
	}

	/// <summary>MOV R11, imm64 (49 BB + 8 bytes)</summary>
	void MovR11(uint64_t imm64)
	{
		Emit(0x49);
		Emit(0xBB);
		EmitQword(imm64);
	}

	/// <summary>MOV R12, imm64 (49 BC + 8 bytes)</summary>
	void MovR12(uint64_t imm64) 
	{
		Emit(0x49);
		Emit(0xBC);
		EmitQword(imm64);
	}

	/// <summary>MOV R13, imm64 (49 BD + 8 bytes)</summary>
	void MovR13(uint64_t imm64)
	{
		Emit(0x49);
		Emit(0xBD);
		EmitQword(imm64);
	}

	/// <summary>MOV R14, imm64 (49 BE + 8 bytes)</summary>
	void MovR14(uint64_t imm64) 
	{
		Emit(0x49);
		Emit(0xBE);
		EmitQword(imm64);
	}

	/// <summary>MOV R15, imm64 (49 BF + 8 bytes)</summary>
	void MovR15(uint64_t imm64) 
	{
		Emit(0x49);
		Emit(0xBF);
		EmitQword(imm64);
	}

	// ============================================================
	// MOV Instructions - Register to Register
	// ============================================================

	/// <summary>MOV RAX, RCX (48 89 C8)</summary>
	void MovRaxRcx() 
	{
		Emit(0x48);
		Emit(0x89);
		Emit(0xC8);
	}

	/// <summary>MOV RCX, RAX (48 89 C1)</summary>
	void MovRcxRax()
	{
		Emit(0x48);
		Emit(0x89);
		Emit(0xC1);
	}

	/// <summary>MOV RDX, RAX (48 89 C2)</summary>
	void MovRdxRax() 
	{
		Emit(0x48);
		Emit(0x89);
		Emit(0xC2);
	}

	// ============================================================
	// MOV Instructions - Memory Operations
	// ============================================================

	/// <summary>MOV [RAX], RCX (48 89 08)</summary>
	void MovPtrRaxRcx() 
	{
		Emit(0x48);
		Emit(0x89);
		Emit(0x08);
	}

	/// <summary>MOV RAX, [RCX] (48 8B 01)</summary>
	void MovRaxPtrRcx()
	{
		Emit(0x48);
		Emit(0x8B);
		Emit(0x01);
	}

	/// <summary>MOV [RCX], RAX (48 89 01)</summary>
	void MovPtrRcxRax()
	{
		Emit(0x48);
		Emit(0x89);
		Emit(0x01);
	}

	/// <summary>MOV RAX, [RAX] (48 8B 00)</summary>
	void MovRaxPtrRax() 
	{
		Emit(0x48);
		Emit(0x8B);
		Emit(0x00);
	}

	/// <summary>MOV [RBX], RAX (48 89 03) - Write RAX to address in RBX</summary>
	void MovPtrRbxRax() 
	{
		Emit(0x48);
		Emit(0x89);
		Emit(0x03);
	}

	void MovDwordPtrRcxEax()
	{
		Emit(0x89);
		Emit(0x01);
	}

	// ============================================================
	// Jump and Call Instructions
	// ============================================================

	/// <summary>JMP RAX (FF E0)</summary>
	void JmpRax() 
	{
		Emit(0xFF);
		Emit(0xE0);
	}

	/// <summary>JMP RCX (FF E1)</summary>
	void JmpRcx() 
	{
		Emit(0xFF);
		Emit(0xE1);
	}

	/// <summary>JMP RDX (FF E2)</summary>
	void JmpRdx()
	{
		Emit(0xFF);
		Emit(0xE2);
	}

	void JmpRbx()
	{
		Emit(0xFF);
		Emit(0xE3);
	}

	/// <summary>JMP rel32 (E9 + 4 bytes offset)</summary>
	void JmpRel32(int32_t offset) 
	{
		Emit(0xE9);
		EmitDword(static_cast<uint32_t>(offset));
	}

	void JmpR10() 
	{
    Emit(0x41); // REX.B
    Emit(0xFF);
    Emit(0xE2);
    }

/// <summary>JMP R11 (41 FF E3)</summary>
void JmpR11() 
{
    Emit(0x41); // REX.B
    Emit(0xFF);
    Emit(0xE3);
}

	static std::vector<uint8_t> CreateAbsoluteJump64(uint64_t targetAddress)
	{
		std::vector<uint8_t> code;
		code.reserve(10);

		// MOV RAX, targetAddress
		code.push_back(0x48); // REX.W
		code.push_back(0xB8); // MOV RAX
		for (int i = 0; i < 8; i++)
		{
			code.push_back(static_cast<uint8_t>(targetAddress >> (i * 8)));
		}

		// JMP RAX
		code.push_back(0xFF);
		code.push_back(0xE0);

		return code;
	}

	/// <summary>CALL RAX (FF D0)</summary>
	void CallRax() 
	{
		Emit(0xFF);
		Emit(0xD0);
	}

	/// <summary>CALL RCX (FF D1)</summary>
	void CallRcx() 
	{
		Emit(0xFF);
		Emit(0xD1);
	}

	/// <summary>CALL rel32 (E8 + 4 bytes offset)</summary>
	void CallRel32(int32_t offset)
	{
		Emit(0xE8);
		EmitDword(static_cast<uint32_t>(offset));
	}

	/// <summary>RET (C3)</summary>
	void Ret()
	{
		Emit(0xC3);
	}

	/// <summary>RET imm16 (C2 + 2 bytes) - Clean stack</summary>
	void Ret(uint16_t stackCleanup) 
	{
		Emit(0xC2);
		EmitWord(stackCleanup);
	}

	// ============================================================
	// Stack Operations
	// ============================================================

	/// <summary>PUSH RAX (50)</summary>
	void PushRax() { Emit(0x50); }

	/// <summary>PUSH RCX (51)</summary>
	void PushRcx() { Emit(0x51); }

	/// <summary>PUSH RDX (52)</summary>
	void PushRdx() { Emit(0x52); }

	/// <summary>PUSH RBX (53)</summary>
	void PushRbx() { Emit(0x53); }

	/// <summary>PUSH RSP (54)</summary>
	void PushRsp() { Emit(0x54); }

	/// <summary>PUSH RBP (55)</summary>
	void PushRbp() { Emit(0x55); }

	/// <summary>PUSH RSI (56)</summary>
	void PushRsi() { Emit(0x56); }

	/// <summary>PUSH RDI (57)</summary>
	void PushRdi() { Emit(0x57); }

	/// <summary>PUSH R8 (41 50)</summary>
	void PushR8() { Emit(0x41); Emit(0x50); }

	/// <summary>PUSH R9 (41 51)</summary>
	void PushR9() { Emit(0x41); Emit(0x51); }

	/// <summary>PUSH R10 (41 52)</summary>
	void PushR10() { Emit(0x41); Emit(0x52); }

	/// <summary>PUSH R11 (41 53)</summary>
	void PushR11() { Emit(0x41); Emit(0x53); }

	// PUSH R12 (41 54)
	void PushR12() { Emit(0x41); Emit(0x54); }

	// PUSH R13 (41 55)
	void PushR13() { Emit(0x41); Emit(0x55); }

	void PushR14() { Emit(0x41); Emit(0x56); }

	// PUSH R15 (41 57)
	void PushR15() { Emit(0x41); Emit(0x57); }



	/// <summary>POP RAX (58)</summary>
	void PopRax() { Emit(0x58); }

	/// <summary>POP RCX (59)</summary>
	void PopRcx() { Emit(0x59); }

	/// <summary>POP RDX (5A)</summary>
	void PopRdx() { Emit(0x5A); }

	/// <summary>POP RBX (5B)</summary>
	void PopRbx() { Emit(0x5B); }

	/// <summary>POP RSP (5C)</summary>
	void PopRsp() { Emit(0x5C); }

	/// <summary>POP RBP (5D)</summary>
	void PopRbp() { Emit(0x5D); }

	/// <summary>POP RSI (5E)</summary>
	void PopRsi() { Emit(0x5E); }

	/// <summary>POP RDI (5F)</summary>
	void PopRdi() { Emit(0x5F); }

	/// <summary>POP R8 (41 58)</summary>
	void PopR8() { Emit(0x41); Emit(0x58); }

	/// <summary>POP R9 (41 59)</summary>
	void PopR9() { Emit(0x41); Emit(0x59); }

	/// <summary>POP R10 (41 5A)</summary>
	void PopR10() { Emit(0x41); Emit(0x5A); }

	/// <summary>POP R11 (41 5B)</summary>
	void PopR11() { Emit(0x41); Emit(0x5B); }


	void PopR12() { Emit(0x41); Emit(0x5C); }

	// POP R13  (41 5D)
	void PopR13() { Emit(0x41); Emit(0x5D); }

	// POP R14  (41 5E)
	void PopR14() { Emit(0x41); Emit(0x5E); }

	// POP R15  (41 5F)
	void PopR15() { Emit(0x41); Emit(0x5F); }


	// Fixed opcode for POP r/m64
	void PopQwordPtrRbx()
	{
		Emit(0x8F);   // POP r/m64
		Emit(0x03);   // ModRM : [RBX]
	}

	/// <summary>SUB RSP, imm8 (48 83 EC + 1 byte)</summary>
	void SubRspImm8(uint8_t imm8)
	{
		Emit(0x48);
		Emit(0x83);
		Emit(0xEC);
		Emit(imm8);
	}

	/// <summary>SUB RSP, imm32 (48 81 EC + 4 bytes)</summary>
	void SubRspImm32(uint32_t imm32) 
	{
		Emit(0x48);
		Emit(0x81);
		Emit(0xEC);
		EmitDword(imm32);
	}

	/// <summary>ADD RSP, imm8 (48 83 C4 + 1 byte)</summary>
	void AddRspImm8(uint8_t imm8) 
	{
		Emit(0x48);
		Emit(0x83);
		Emit(0xC4);
		Emit(imm8);
	}

	/// <summary>ADD RSP, imm32 (48 81 C4 + 4 bytes)</summary>
	void AddRspImm32(uint32_t imm32) 
	{
		Emit(0x48);
		Emit(0x81);
		Emit(0xC4);
		EmitDword(imm32);
	}

	// ============================================================
	// Arithmetic and Logic
	// ============================================================

	/// <summary>XOR RAX, RAX (48 31 C0) - Zero out RAX</summary>
	void XorRaxRax() 
	{
		Emit(0x48);
		Emit(0x31);
		Emit(0xC0);
	}

	/// <summary>XOR RCX, RCX (48 31 C9) - Zero out RCX</summary>
	void XorRcxRcx()
	{
		Emit(0x48);
		Emit(0x31);
		Emit(0xC9);
	}

	/// <summary>XOR RDX, RDX (48 31 D2) - Zero out RDX</summary>
	void XorRdxRdx() 
	{
		Emit(0x48);
		Emit(0x31);
		Emit(0xD2);
	}

	/// <summary>ADD RAX, imm32 (48 05 + 4 bytes)</summary>
	void AddRaxImm32(uint32_t imm32)
	{
		Emit(0x48);
		Emit(0x05);
		EmitDword(imm32);
	}

	/// <summary>SUB RAX, imm32 (48 2D + 4 bytes)</summary>
	void SubRaxImm32(uint32_t imm32)
	{
		Emit(0x48);
		Emit(0x2D);
		EmitDword(imm32);
	}

	// ============================================================
	// Special Instructions
	// ============================================================

	/// <summary>NOP (90) - No operation</summary>
	void Nop() 
	{
		Emit(0x90);
	}

	/// <summary>INT3 (CC) - Breakpoint for debugging</summary>
	void Int3()
	{
		Emit(0xCC);
	}

	/// <summary>PUSHFQ (9C) - Push RFLAGS</summary>
	void Pushfq()
	{
		Emit(0x9C);
	}

	/// <summary>POPFQ (9D) - Pop RFLAGS</summary>
	void Popfq()
	{
		Emit(0x9D);
	}

	/// <summary>CLI (FA) - Clear interrupt flag</summary>
	void Cli()
	{
		Emit(0xFA);
	}

	/// <summary>STI (FB) - Set interrupt flag</summary>
	void Sti() 
	{
		Emit(0xFB);
	}

	// ============================================================
	// Utility Methods
	// ============================================================

	/// <summary>Get current code size in bytes</summary>
	size_t Size() const 
	{
		return code.size();
	}

	/// <summary>Get the generated bytecode as vector</summary>
	const std::vector<uint8_t>& GetBytes() const
	{
		return code;
	}

	/// <summary>Get raw pointer to bytecode</summary>
	const uint8_t* Data() const 
	{
		return code.data();
	}

	/// <summary>Clear all generated code</summary>
	void Clear()
	{
		code.clear();
	}

	/// <summary>Reserve space for expected code size (optimization)</summary>
	void Reserve(size_t size) 
	{
		code.reserve(size);
	}

	/// <summary>Align code to boundary with NOPs (for performance)</summary>
	void AlignTo(size_t alignment) 
	{
		while (code.size() % alignment != 0)
		{
			Nop();
		}
	}

	/// <summary>Add raw bytes directly</summary>
	void EmitRawBytes(const uint8_t* bytes, size_t count) 
	{
		for (size_t i = 0; i < count; ++i)
		{
			Emit(bytes[i]);
		}
	}

	// ============================================================
	// High-Level Helper Functions
	// ============================================================

	/// <summary>
	/// Create a simple hook: MOV RAX + JMP RAX (12 bytes)
	/// Perfect for hooking kernel functions
	/// </summary>


	static inline std::mt19937_64& GetRNG()
	{
		thread_local std::mt19937_64 rng{ std::random_device{}() }; // Seed with random device, thread-local$
		return rng;                                                 // Warning tho, this is not cryptographically secure
		                                                            // And if random_device is not available, it may be deterministic
	}


	static std::vector<uint8_t> CreateSimpleHook(uint64_t targetAddress)
	{
		X64Assembler asm_builder;
		asm_builder.MovRax(targetAddress);
		asm_builder.JmpRax();
		return asm_builder.GetBytes();
	}

	/// <summary>
	/// Create a trampoline hook that preserves full context,
	/// Calls hook function, then returns to original execution
	/// </summary>
	static std::vector<uint8_t> CreateTrampolineHook(
		uint64_t hookFunction,
		uint64_t returnAddress,
		bool preserveFlags = true)
	{
		X64Assembler asm_builder;

		// 1. Save ALL registers
		if (preserveFlags) asm_builder.Pushfq();  // +8

		// Volatile
		asm_builder.PushRax();   // +8
		asm_builder.PushRcx();   // +8
		asm_builder.PushRdx();   // +8
		asm_builder.PushR8();    // +8
		asm_builder.PushR9();    // +8
		asm_builder.PushR10();   // +8
		asm_builder.PushR11();   // +8

		// Non-volatile
		asm_builder.PushRbx();   // +8
		asm_builder.PushRbp();   // +8
		asm_builder.PushRsi();   // +8
		asm_builder.PushRdi();   // +8
		asm_builder.PushR12();   // +8
		asm_builder.PushR13();   // +8
		asm_builder.PushR14();   // +8
		asm_builder.PushR15();   // +8

		// Total: 15 registers = 120 bytes (with RFLAGS) ou 112 bytes (without)

		// Calculate stack alignment
		size_t pushed_bytes = preserveFlags ? 120 : 112;
		size_t alignment_needed = (16 - ((pushed_bytes + 8) % 16)) % 16;
		uint32_t total_alloc = 0x20 + static_cast<uint32_t>(alignment_needed);

		if (total_alloc <= 0xFF)
			asm_builder.SubRspImm8(static_cast<uint8_t>(total_alloc));
		else
			asm_builder.SubRspImm32(total_alloc);

		// Call hook
		asm_builder.MovRax(hookFunction);
		asm_builder.CallRax();

		// Cleanup stack
		if (total_alloc <= 0xFF)
			asm_builder.AddRspImm8(static_cast<uint8_t>(total_alloc));
		else
			asm_builder.AddRspImm32(total_alloc);

		// Restore registers (REVERSE ORDER!)
		asm_builder.PopR15();
		asm_builder.PopR14();
		asm_builder.PopR13();
		asm_builder.PopR12();
		asm_builder.PopRdi();
		asm_builder.PopRsi();
		asm_builder.PopRbp();
		asm_builder.PopRbx();

		asm_builder.PopR11();
		asm_builder.PopR10();
		asm_builder.PopR9();
		asm_builder.PopR8();
		asm_builder.PopRdx();
		asm_builder.PopRcx();
		asm_builder.PopRax();

		if (preserveFlags) asm_builder.Popfq();

		// Return to original code
		asm_builder.MovRax(returnAddress);
		asm_builder.JmpRax();

		return asm_builder.GetBytes();
	}

	/// <summary>
/// Create function call shellcode with Windows x64 calling convention
/// Args: RCX, RDX, R8, R9 (first 4 params)
/// Returns: Result in RAX
/// Note: Caller must ensure stack is 16-byte aligned on entry
/// </summary>
	static std::vector<uint8_t> CreateFunctionCall(
		uint64_t functionAddress,
		uint64_t arg1 = 0,
		uint64_t arg2 = 0,
		uint64_t arg3 = 0,
		uint64_t arg4 = 0)
	{
		X64Assembler asm_builder;

		//    Save volatile registers (RAX will hold function address temporarily)
		//    We DON'T save RCX, RDX, R8, R9 because we're about to overwrite them
		//    with arguments (volatile anyway)
		asm_builder.PushR10();
		asm_builder.PushR11();
		// Total pushed: 2 × 8 = 16 bytes

		//    Allocate shadow space + ensure alignment
		//    After 2 PUSH: RSP = original - 16
		//    Need: (RSP - shadow - 8) % 16 == 0 before CALL
		//    So: (16 + shadow + 8) % 16 == 0
		//    => shadow = 32 works: (16 + 32 + 8) % 16 = 8 % 16 NOPE....
		//    Need 8 more bytes: shadow = 32 + 8 = 40
		asm_builder.SubRspImm8(0x28);  // 40 bytes (32 shadow + 8 align)

		asm_builder.MovRcx(arg1);
		asm_builder.MovRdx(arg2);
		asm_builder.MovR8(arg3);
		asm_builder.MovR9(arg4);

		asm_builder.MovRax(functionAddress);
		asm_builder.CallRax();
		// Result is now in RAX

		asm_builder.AddRspImm8(0x28);

		asm_builder.PopR11();
		asm_builder.PopR10();

		asm_builder.Ret();

		return asm_builder.GetBytes();
	}

	/// <summary>
/// Create function call shellcode with full register preservation
/// Supports up to 8 arguments (4 in registers + 4 on stack)
/// </summary>
	static std::vector<uint8_t> CreateFunctionCallEx(
		uint64_t functionAddress,
		const std::vector<uint64_t>& args)
	{
		X64Assembler asm_builder;

		if (args.size() > 8)
		{
			// Fallback to basic version or throw
			return {};
		}

		// 1. Save ALL volatile registers (we'll restore RAX later for return value)
		asm_builder.PushRax();  // Will be used for function address
		asm_builder.PushRcx();  // Will be overwritten with arg1
		asm_builder.PushRdx();  // Will be overwritten with arg2
		asm_builder.PushR8();   // Will be overwritten with arg3
		asm_builder.PushR9();   // Will be overwritten with arg4
		asm_builder.PushR10();
		asm_builder.PushR11();
		// Total pushed: 7 × 8 = 56 bytes

		// 2. Calculate stack allocation
		//    Shadow space: 32 bytes (mandatory)
		//    Extra args: (args.size() > 4) ? (args.size() - 4) × 8 : 0
		//    Alignment: ensure (56 + allocated + 8) % 16 == 0

		size_t extra_args = (args.size() > 4) ? (args.size() - 4) : 0;
		size_t base_alloc = 32 + (extra_args * 8);
		size_t pushed_bytes = 56;
		size_t alignment = (16 - ((pushed_bytes + base_alloc + 8) % 16)) % 16;
		size_t total_alloc = base_alloc + alignment;

		if (total_alloc <= 0xFF)
			asm_builder.SubRspImm8(static_cast<uint8_t>(total_alloc));
		else
			asm_builder.SubRspImm32(static_cast<uint32_t>(total_alloc));

		// 3. Setup register arguments (first 4)
		if (args.size() > 0) asm_builder.MovRcx(args[0]);
		if (args.size() > 1) asm_builder.MovRdx(args[1]);
		if (args.size() > 2) asm_builder.MovR8(args[2]);
		if (args.size() > 3) asm_builder.MovR9(args[3]);

		// 4. Setup stack arguments (5th+)
		//    Stack layout after SubRsp:
		//    [RSP+0x00] = shadow space for RCX
		//    [RSP+0x08] = shadow space for RDX
		//    [RSP+0x10] = shadow space for R8
		//    [RSP+0x18] = shadow space for R9
		//    [RSP+0x20] = 5th argument
		//    [RSP+0x28] = 6th argument
		//    etc.

		for (size_t i = 4; i < args.size(); ++i)
		{
			// safer
			uint64_t offset64 = 0x20ULL + ((i - 4) * 8ULL);

			// Check if the offset fit in 32 bits
			if (offset64 > 0xFFFFFFFFULL)
			{
				throw std::runtime_error("Stack offset too large");
			}

			uint32_t stack_offset = static_cast<uint32_t>(offset64);

			// Debug output
			printf("i=%zu, offset=0x%X\n", i, stack_offset);

			asm_builder.MovRax(args[i]);

			asm_builder.Emit(0x48);
			asm_builder.Emit(0x89);
			asm_builder.Emit(0x84);
			asm_builder.Emit(0x24);
			asm_builder.EmitDword(stack_offset);
		}

		asm_builder.MovRax(functionAddress);
		asm_builder.CallRax();

		asm_builder.PushRax();

		if (total_alloc <= 0xFF)
			asm_builder.AddRspImm8(static_cast<uint8_t>(total_alloc));
		else
			asm_builder.AddRspImm32(static_cast<uint32_t>(total_alloc));

		asm_builder.PopR10(); 

		asm_builder.PopR11();
		asm_builder.PopR10();  // This pops the OLD R10 value we saved in step 1
		asm_builder.PopR9();
		asm_builder.PopR8();
		asm_builder.PopRdx();
		asm_builder.PopRcx();
		asm_builder.PopRax();  // Discard old RAX


		asm_builder.Ret();

		return asm_builder.GetBytes();
	}

	/// <summary>
	/// Save all volatile registers (Microsoft x64 ABI)
	/// Volatile: RAX, RCX, RDX, R8-R11
	/// </summary>
	void SaveVolatileRegisters()
	{
		PushRax();
		PushRcx();
		PushRdx();
		PushR8();
		PushR9();
		PushR10();
		PushR11();
	}

	/// <summary>
	/// Restore all volatile registers (reverse order)
	/// </summary>
	void RestoreVolatileRegisters()
	{
		PopR11();
		PopR10();
		PopR9();
		PopR8();
		PopRdx();
		PopRcx();
		PopRax();
	}

	/// <summary>
	/// Save all non-volatile registers (Microsoft x64 ABI)
	/// Non-volatile: RBX, RBP, RDI, RSI, RSP, R12-R15
	/// </summary>
	void SaveNonVolatileRegisters()
	{
		PushRbx();
		PushRbp();
		PushRdi();
		PushRsi();
		PushR12();
		PushR13();
		PushR14();
		PushR15();
	}

	/// <summary>
	/// Restore all non-volatile registers (reverse order)
	/// </summary>
	void RestoreNonVolatileRegisters() {

		PopR15();
		PopR14();
		PopR13();
		PopR12();
		PopRsi();
		PopRdi();
		PopRbp();
		PopRbx();
	}

	/// <summary>
	/// Create a minimal hook stub (just the trampoline part)
	/// User must provide stolen bytes separately
	/// </summary>
	static std::vector<uint8_t> CreateMinimalHook(uint64_t targetAddress) 
	{
		X64Assembler asm_builder;
		asm_builder.MovRax(targetAddress);
		asm_builder.JmpRax();
		return asm_builder.GetBytes();
	}

	/// <summary>
	/// Calculate relative offset for JMP/CALL rel32
	/// </summary>
	static std::optional<int32_t> CalculateRelativeOffset(
		uint64_t fromAddress,
		uint64_t toAddress,
		size_t instructionSize = 5) // JMP/CALL rel32 = 5 bytes
	{
		int64_t offset = static_cast<int64_t>(toAddress) -
			(static_cast<int64_t>(fromAddress) + instructionSize);

		// Check if offset fits in 32-bit signed integer
		if (offset > INT32_MAX || offset < INT32_MIN)
		{
			return std::nullopt; // Offset too large
		}

		return static_cast<int32_t>(offset);
	}


	



/// NOTE : This func is part of Valkyrie and may not be generic enough for all uses cases.
// 	 Write your own tailored to your needs.
	static std::vector<uint8_t> PolymorphicHook(uint64_t targetAddress, size_t maxSafeSize = 12)
	{
		std::vector<uint8_t> code;
		auto& rng = GetRNG();

		enum JumpTechnique 
		{
			MOV_RAX_JMP_RAX,    // 48 B8 [addr] FF E0 = 12 bytes 
			MOV_RBX_JMP_RBX,    // 48 BB [addr] FF E3 = 12 bytes 
		
		};

		JumpTechnique tech = static_cast<JumpTechnique>(rng() % 2);

		switch (tech) 
		{
		case MOV_RAX_JMP_RAX:
			// MOV RAX + JMP RAX (12 bytes)
			code.insert(code.end(), { 0x48, 0xB8 });
			for (int i = 0; i < 8; i++)
				code.push_back((targetAddress >> (i * 8)) & 0xFF);
			code.insert(code.end(), { 0xFF, 0xE0 });
			break;
		

		case MOV_RBX_JMP_RBX:
			// MOV RBX + JMP RBX (12 bytes)
			code.insert(code.end(), { 0x48, 0xBB });
			for (int i = 0; i < 8; i++)
				code.push_back((targetAddress >> (i * 8)) & 0xFF);
			code.insert(code.end(), { 0xFF, 0xE3 });
			break;

		}

		if (code.size() != 12) 
		{
			std::cout << "Error ! Hook is " << code.size() << " instead of 12! Using fallback..." << std::endl;
			code = 
			{
				0x48, 0xB8, // MOV RAX
				(uint8_t)(targetAddress >> 0), (uint8_t)(targetAddress >> 8),
				(uint8_t)(targetAddress >> 16), (uint8_t)(targetAddress >> 24),
				(uint8_t)(targetAddress >> 32), (uint8_t)(targetAddress >> 40),
				(uint8_t)(targetAddress >> 48), (uint8_t)(targetAddress >> 56),
				0xFF, 0xE0  // JMP RAX
			};
		}

		std::cout << "Generating hook..." << std::endl;
		std::cout << "Technique: ";

		switch (tech) 
		{
		case MOV_RAX_JMP_RAX: std::cout << "MOV RAX + JMP RAX"; break;
		case MOV_RBX_JMP_RBX: std::cout << "MOV RBX + JMP RBX"; break;
		}

		std::cout << "\nsize: " << code.size() << " bytes" << std::endl;
		std::cout << "Bytes: ";

		for (auto b : code) printf("%02X ", b);
		std::cout << "\nTarget: 0x" << std::hex << targetAddress << std::dec << std::endl;

		return code;
	}
/// <summary>
/// Create immediate return (5 bytes) - MOV EAX + RET
/// Perfect for syscall hooks that need to return immediately
/// </summary>
	static std::vector<uint8_t> CreateImmediateReturn(uint32_t returnValue = 0) 
	{
		return 
		{
			0xB8, // MOV EAX, imm32
			static_cast<uint8_t>(returnValue),
			static_cast<uint8_t>(returnValue >> 8),
			static_cast<uint8_t>(returnValue >> 16),
			static_cast<uint8_t>(returnValue >> 24),
			0xC3  // RET
		};
	}

	/// <summary>
	/// Check if two addresses are within ±2GB range for relative jumps
	/// </summary>
	static bool IsWithinRelativeRange(uint64_t fromAddress, uint64_t toAddress, size_t instructionSize = 5)
	{
		auto offset = CalculateRelativeOffset(fromAddress, toAddress, instructionSize);
		return offset.has_value();
	}

	/// <summary>
	/// Create NOP slide of specified size
	/// </summary>
	static std::vector<uint8_t> CreateNopSlide(size_t size)
	{
		std::vector<uint8_t> nops;
		nops.reserve(size + 8); 

		while (nops.size() < size)
		{
			if (!EmitRandomNopV2(nops, size - nops.size()))
				break;
		}

		nops.resize(size); 
		return nops;
	}

	static void AddRandomNops(std::vector<uint8_t>& code, size_t desiredCount, size_t maxTotalSize) 
	{
		size_t remainingSpace = maxTotalSize - code.size();
		size_t actualCount = std::min(desiredCount, remainingSpace);

		for (size_t i = 0; i < actualCount; ++i)
		{
			size_t currentRemaining = maxTotalSize - code.size();
			if (currentRemaining == 0) break;

			if (!EmitRandomNopV2(code, currentRemaining)) 
			{
				break; 
			}
		}
	}


};