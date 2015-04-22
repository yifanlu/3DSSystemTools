#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <3ds.h>

#include "constants.h"
#include "patches.h"
#include "kernel11.h"
#include "kobjects.h"

//-----------------------------------------------------------------------------

u32 self_pid = 0;

int PatchPid()
{
    *(u32*)(curr_kproc_addr + kproc_pid_offset) = 0;
    return 0;
}

int UnpatchPid()
{
    *(u32*)(curr_kproc_addr + kproc_pid_offset) = self_pid;
    return 0;
}

void ReinitSrv()
{
    srvExit();
    srvInit();
}

void PatchSrvAccess()
{
    svcGetProcessId(&self_pid, 0xFFFF8001);
    printf("Current process id: %lu\n", self_pid);

    printf("Patching srv access...");
    KernelBackdoor(PatchPid);
    ReinitSrv();

    u32 new_pid;
    svcGetProcessId(&new_pid, 0xFFFF8001);
    printf("%s\n", new_pid == 0 ? "succeeded!" : "failed!");

    // Cleanup; won't take effect until srv is reinitialized
    KernelBackdoor(UnpatchPid);
}

//-----------------------------------------------------------------------------

int PatchProcess()
{
    KCodeSet* code_set = FindTitleCodeSet("fs", 2);
    if (code_set == nullptr)
        return 1;
    
    *(u32*)FindCodeOffsetKAddr(code_set, 0x00028978) = 0xe3800901;
    *(u32*)FindCodeOffsetKAddr(code_set, 0x00028AB8) = 0xe3800901;
    return 0;
}