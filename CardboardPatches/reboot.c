/*
 * uvloader.c - Userland Vita Loader entry point
 * Copyright 2012 Yifan Lu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define START_SECTION __attribute__ ((section (".text.start")))

// make sure code is PIE
#ifndef __PIE__
#error "Must compile with -fPIE"
#endif

/********************************************//**
 *  \brief Starting point from exploit
 *
 *  Call this from your exploit to run UVLoader.
 *  It will first cache all loaded modules and
 *  attempt to resolve its own NIDs which
 *  should only depend on sceLibKernel.
 *  \returns Zero on success, otherwise error
 ***********************************************/

int START_SECTION
uvl_start (void)
{
    char *param1 = 0x0030C240;
    char *param2 = 0x0030C540;
    int (*prepare_app_jump)(unsigned long long tid, int mediatype) = 0x001050FC;
    int (*do_app_jump)(char *param1, char *param2) = 0x0010C594;
    int (*delete_extdata)(unsigned long long extid) = 0x0010B028;
    param1[0] = 0x82;
    //delete_extdata(0xE0000000LL);
    prepare_app_jump(0x4001000021A00LL, 0);
    do_app_jump(param1, param2);

    while (1);

    return 0;
}
