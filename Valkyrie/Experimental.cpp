#include "Experimental.hpp"

#include "Common.hpp"
#include "IntelLoader.hpp"


// TODO :

// 1. Trampoline randomisation
//    – build a pool of zero-effect syscalls
//    – pick one at random for each KInvoke → signature becomes a lottery
//    – rotate the pool every call to become fucking annoying.

// 2. Enhanced polymorphic shellcode
//    – 12-byte hook now uses register roulette (RAX, RBX)
//    - keep working on usable jumps techniques to add variety

// 3. HVCI & CET readiness
//    – detect HVCI presence → fallback to WHQL-signed driver + ETW tamper
//    – if CET enabled → use indirect-branch compatible trampolines (no jmp reg, use jmp [mem] with forged IBT)


// 6. Registry stealth v2
//    – DKOM the service key : zero-out DriverName in-memory → no registry write logged
//    – shuffle delete order : unload → random delay → delete key → random delay → delete file

// 7. IOCTL cloaking
//    ???...

// 8. Nope.mp4 not gonna allow another memory allocating methode for now. So playing with pool tags
//    is irrelevant. Maybe later.

// 9. Time-based evasion
//    – random sleep 0-500 ms between each kernel call → breaks timing signatures
//    – randomise order : map → wipe → clean → sleep → unload → delete


// 10. Sandbox, VM, debugger & hook detection.