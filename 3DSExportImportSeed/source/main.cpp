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
    FSUSER_ImportIntegrityVerificationSeed(seed);
    printf("Import seed done.\n");
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

    khaxExit();
    hbExit();
    gfxExit();
    return 0;
}
