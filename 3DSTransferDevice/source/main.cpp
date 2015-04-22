#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <3ds.h>

#include "khax.h"
#include "constants.h"
#include "kernel11.h"
#include "patches.h"

#define log(...) fprintf(stderr, __VA_ARGS__)

extern "C" Handle fsuHandle;
static Handle cfgHandle;

static Result CFG_SetGetLocalFriendCodeSeedData(u8 *data)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x080B0082;
  cmdbuf[1] = 0x10;
  cmdbuf[2] = 0;
  cmdbuf[3] = (0x10 << 4) | 12;
  cmdbuf[4] = (u32)data;

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
  cmdbuf[3] = (u32)data;

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
  cmdbuf[4] = (u32)data;
  cmdbuf[5] = (sigsize << 4) | 10;
  cmdbuf[6] = (u32)sig;

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
  cmdbuf[2] = (u32)data;

  if((ret = svcSendSyncRequest(fsuHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result FSUSER_ImportIntegrityVerificationSeed(const u8 *data)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x084B0002;
  cmdbuf[1] = (0x130 << 8) | 10;
  cmdbuf[2] = (u32)data;

  if((ret = svcSendSyncRequest(fsuHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static Result FSUser_InitializeCtrFileSystem(void)
{
  Result ret = 0;
  u32 *cmdbuf = getThreadCommandBuffer();

  cmdbuf[0] = 0x08430000;

  if((ret = svcSendSyncRequest(fsuHandle))!=0) return ret;
  
  return (Result)cmdbuf[1];
}

static void DoExportSeed(void)
{
  FILE *file;
  Result res;
  u8 seed[0x130];

  res = FSUSER_ExportIntegrityVerificationSeed(seed);
  printf("FSUSER_ExportIntegrityVerificationSeed: 0x%08X\n", res);
  if (res != 0) return;

  file = fopen("sdmc:/export_seed.bin", "wb");
  fwrite(seed, 0x130, 1, file);
  fclose(file);
  printf("Export seed done.\n");
}

static void DoImportSeed(void)
{
  FILE *file;
  Result res;
  u8 seed[0x130];

  file = fopen("sdmc:/export_seed.bin", "rb");
  if (fread(seed, 0x130, 1, file) < 1)
  {
    printf("Error reading seed.\n");
  }
  else
  {
    res = FSUSER_ImportIntegrityVerificationSeed(seed);
    printf("FSUSER_ImportIntegrityVerificationSeed: 0x%08X\n", res);
  }
  fclose(file);
}

static void DoFormatCTRNand(void)
{
  Result res;

  res = FSUser_InitializeCtrFileSystem();
  printf("FSUSER_InitializeCtrFileSystem: 0x%08X\n", res);

  return;
}

static void DoImportSecureInfo(void)
{
  FILE *file;
  Result res;
  u8 secureinfo[0x111];

  if ((file = fopen("sdmc:/SecureInfo_A", "rb")) == NULL)
  {
    printf("Cannot find SecureInfo_A\n");
    return;
  }
  if (fread(secureinfo, sizeof(secureinfo), 1, file) < 1)
  {
    printf("Error reading secure info\n");
    fclose(file);
    return;
  }
  fclose(file);

  res = CFG_SetSecureInfo(&secureinfo[0x100], 0x11, secureinfo, 0x100);
  printf("CFG_SetSecureInfo: 0x%08X\n", res);
  if (res != 0) return;

  res = CFG_VerifySigSecureInfo();
  printf("CFG_VerifySigSecureInfo: 0x%08X\n", res);
  if (res != 0) return;

  res = CFG_DeleteCreateNANDSecureInfo();
  printf("CFG_DeleteCreateNANDSecureInfo: 0x%08X\n", res);
  
  printf("Finished.\n");
}

int main(int argc, char** argv)
{
    Result res;

    gfxInitDefault();
    hbInit();
    consoleInit(GFX_TOP, NULL);

    res = khaxInit();
    printf("khaxInit returned %08lx\n", res);

    SaveVersionConstants();
    PatchSrvAccess();
    printf("[%08X] Patched process\n", KernelBackdoor(PatchProcess));
    HB_FlushInvalidateCache(); // Just to be sure!
    if ((res = srvGetServiceHandle(&cfgHandle, "cfg:i")) != 0)
    {
      printf("Error 0x%08X initializing cfg.\n", res);
      svcSleepThread(10000000000ULL);
      goto end;
    }

    printf("Press A to install SecureInfo.\n");
    printf("Press X to export seed.\n");
    printf("Press Y to import seed.\n");
    printf("Press Select to format CTRNAND.\n");
    printf("Press Start to exit.\n");

    // Main loop
    while (aptMainLoop())
    {
        hidScanInput();

        u32 kDown = hidKeysDown();
        if (kDown & KEY_START)
            break;
        if (kDown & KEY_SELECT)
        {
            DoFormatCTRNand();
        }
        if (kDown & KEY_A)
        {
            DoImportSecureInfo();
        }
        if (kDown & KEY_X)
        {
            DoExportSeed();
        }
        if (kDown & KEY_Y)
        {
            DoImportSeed();
        }
        gspWaitForVBlank();
    }

end:
    khaxExit();
    hbExit();
    gfxExit();
    return 0;
}
