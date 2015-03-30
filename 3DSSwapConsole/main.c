#include <3ds.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>

#include "bootstrap.h"

static const u32 KPROC_OFFSET_PID_O3DS = 0xB4;
static const u32 KPROC_OFFSET_PID_N3DS = 0xBC;

static u32 kproc_offset_pid;
static u32 self_pid;
static u32 curr_kproc;
static Handle cfgHandle = 0;
extern Handle fsuHandle;
static Handle fsregHandle;

// service patching code thanks to archshift
int __attribute__((naked))
    arm11_kernel_execute(int (*func)(void))
{
    asm volatile ("svc #0x7B \t\n"
                  "bx lr     \t\n");
}

int patch_pid() {
    // 0xFFFF9004 always points to the current KProcess
    curr_kproc = *(u32*)0xFFFF9004;
    *(u32*)(curr_kproc + kproc_offset_pid) = 0;
    return 0;
}

int unpatch_pid() {
    *(u32*)(curr_kproc + kproc_offset_pid) = self_pid;
    return 0;
}

void reinit_srv() {
    srvExit();
    srvInit();
}

void patch_srv_access() {
  u8 isN3DS = 0;
  APT_CheckNew3DS(NULL, &isN3DS);
  kproc_offset_pid = isN3DS ? KPROC_OFFSET_PID_N3DS : KPROC_OFFSET_PID_O3DS;

    svcGetProcessId(&self_pid, 0xFFFF8001);
    printf("Current process id: %lu\n", self_pid);

    printf("Patching srv access...");
    arm11_kernel_execute(patch_pid);
    reinit_srv();

    u32 new_pid;
    svcGetProcessId(&new_pid, 0xFFFF8001);
    printf("%s\n", new_pid == 0 ? "succeeded!" : "failed!");

    // Cleanup; won't take effect until srv is reinitialized
    arm11_kernel_execute(unpatch_pid);
}

static Result CFG_SetGetLocalFriendCodeSeedData(u8 *data)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x080B0082;
  cmdbuf[1] = 0x10;
  cmdbuf[2] = 0;
  cmdbuf[3] = (0x10 << 4) | 12;
  cmdbuf[4] = data;

  if((ret = svcSendSyncRequest(cfgHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result CFG_SetLocalFriendCodeSeedSignature(const u8 *data, u32 size)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x080C0042;
  cmdbuf[1] = size;
  cmdbuf[2] = (size << 4) | 10;
  cmdbuf[3] = data;

  if((ret = svcSendSyncRequest(cfgHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result CFG_VerifySigLocalFriendCodeSeed(void)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x080E0000;

  if((ret = svcSendSyncRequest(cfgHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result CFG_SetSecureInfo(const u8 *data, u32 size, const u8 *sig, u32 sigsize)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x08110084;
  cmdbuf[1] = size;
  cmdbuf[2] = sigsize;
  cmdbuf[3] = (size << 4) | 10;
  cmdbuf[4] = data;
  cmdbuf[5] = (sigsize << 4) | 10;
  cmdbuf[6] = sig;

  if((ret = svcSendSyncRequest(cfgHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result CFG_VerifySigSecureInfo(void)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x08130000;

  if((ret = svcSendSyncRequest(cfgHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result CFG_DeleteCreateNANDSecureInfo(void)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x08120000;

  if((ret = svcSendSyncRequest(cfgHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result FSUSER_ExportIntegrityVerificationSeed(u8 *data)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x084A0002;
  cmdbuf[1] = (0x130 << 8) | 12;
  cmdbuf[2] = data;

  if((ret = svcSendSyncRequest(fsuHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result FSUSER_ImportIntegrityVerificationSeed(const u8 *data)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x084B0002;
  cmdbuf[1] = (0x130 << 8) | 10;
  cmdbuf[2] = data;

  if((ret = svcSendSyncRequest(fsuHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result ReinitFSServices(void)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x04020040;
  cmdbuf[1] = self_pid;

  printf("Unregistering process %d\n", self_pid);
  if((ret = svcSendSyncRequest(fsregHandle))!=0) return ret;
  if(cmdbuf[1] != 0) return (Result)cmdbuf[1];

  memset(cmdbuf, 0, 16 * 4);
  cmdbuf[0] = 0x040103C0;
  cmdbuf[1] = self_pid;
  *(u64*)&cmdbuf[2] = 0x0043030000000400;
  *(u64*)&cmdbuf[4] = 0x0043030000000400;
  cmdbuf[6] = 2;
  cmdbuf[7] = 0;
  cmdbuf[8+6] = 0xFFFFFFFF;
  cmdbuf[8+7] = 0xFFFFFFFF;

  printf("Registering process %d\n", self_pid);
  if((ret = svcSendSyncRequest(fsregHandle))!=0) return ret;
  if(cmdbuf[1] != 0) return (Result)cmdbuf[1];

  printf("Restarting fs service\n");
  fsExit();
  fsInit();

  return 0;
}

int main()
{
  FILE *file;
  Result res;
  char overflow[8];
  char seed[0x130];
  char friendcodeseed[0x110];
  char secureinfo[0x111];

  // Initialize services
  gfxInitDefault(); // graphics
  hbInit();

  consoleInit(GFX_TOP, NULL);

  int tries = 5;
  while (!doARM11Hax() && tries-- > 0);
  patch_srv_access();

  printf("ARM11 service patched!\n\n");
  if ((res = srvGetServiceHandle(&cfgHandle, "cfg:i")) != 0)
  {
    printf("Error 0x%08X initializing cfg.\n", res);
    svcSleepThread(10000000000ULL);
    goto end;
  }
  /*
  printf("Getting fs:REG\n");
  if ((res = srvGetServiceHandle(&fsregHandle, "fs:REG")) != 0)
  {
    printf("Error 0x%08X initializing fs:REG.\n", res);
    svcSleepThread(10000000000ULL);
    goto end;
  }
  printf("Services obtained.\n");

  if ((res = ReinitFSServices()) != 0)
  {
    printf("Error 0x%08X\n", res);
    svcSleepThread(10000000000ULL);
    goto end;
  }
  */

  printf("Press A to install.\n");
  //printf("Press X to export.\n");
  printf("Press B to exit without installing.\n");

  while(aptMainLoop())
  {
    //exit when user hits B
    hidScanInput();
    if(keysHeld()&KEY_B)goto error_no_wait;
    //if(keysHeld()&KEY_X)goto do_export;
    if(keysHeld()&KEY_A)goto do_import;

    //wait & swap
    gfxFlushBuffers();
    gfxSwapBuffersGpu();
    gspWaitForVBlank();
  }

do_export:
  res = FSUSER_ExportIntegrityVerificationSeed(seed);
  printf("FSUSER_ExportIntegrityVerificationSeed: 0x%08X\n", res);
  if (res != 0) goto error;

  file = fopen("sdmc:/export_seed.bin", "wb");
  fwrite(seed, 0x130, 1, file);
  fclose(file);
  printf("Export seed done.\n");

  goto error;

do_import:
  if ((file = fopen("sdmc:/LocalFriendCodeSeed_B", "rb")) == NULL)
  {
    printf("Cannot find LocalFriendCodeSeed_B\n");
    goto error;
  }
  if (fread(friendcodeseed, sizeof(friendcodeseed), 1, file) < 1)
  {
    printf("Error reading friend code seed\n");
    fclose(file);
    goto error;
  }
  fclose(file);

  if ((file = fopen("sdmc:/SecureInfo_A", "rb")) == NULL)
  {
    printf("Cannot find SecureInfo_A\n");
    goto error;
  }
  if (fread(secureinfo, sizeof(secureinfo), 1, file) < 1)
  {
    printf("Error reading secure info\n");
    fclose(file);
    goto error;
  }
  fclose(file);

  /*
  memset(overflow, 0, sizeof(overflow));
  res = CFG_SetGetLocalFriendCodeSeedData(&friendcodeseed[0x100]);
  printf("CFG_SetGetLocalFriendCodeSeedData: 0x%08X\n", res);
  if (res != 0) goto error;
  printf("Data: 0x%Xll\n", *(u64*)overflow);

  res = CFG_SetLocalFriendCodeSeedSignature(friendcodeseed, 0x100);
  printf("CFG_SetLocalFriendCodeSeedSignature: 0x%08X\n", res);
  if (res != 0) goto error;

  res = CFG_VerifySigLocalFriendCodeSeed();
  printf("CFG_VerifySigLocalFriendCodeSeed: 0x%08X\n", res);
  if (res != 0) goto error;
  */

  res = CFG_SetSecureInfo(&secureinfo[0x100], 0x11, secureinfo, 0x100);
  printf("CFG_SetSecureInfo: 0x%08X\n", res);
  if (res != 0) goto error;

  res = CFG_VerifySigSecureInfo();
  printf("CFG_VerifySigSecureInfo: 0x%08X\n", res);
  if (res != 0) goto error;

  res = CFG_DeleteCreateNANDSecureInfo();
  printf("CFG_DeleteCreateNANDSecureInfo: 0x%08X\n", res);
  
  printf("Finished.\n");

  // Exit services
  //returning from main() returns to hbmenu when run under ninjhax
error:
  gfxFlushBuffers();
  gfxSwapBuffersGpu();
  svcSleepThread(10000000000ULL);
error_no_wait:
  svcCloseHandle(cfgHandle);
  //svcCloseHandle(fsregHandle);
end:
  //closing all services even more so
  hbExit();
  gfxExit();

  *(u32*)NULL = NULL;

  return 0;
}
