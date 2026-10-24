// SSOExternal.cpp — PXScript executor via code caves (PoC)
// Addresses must be provided as RVAs on the command line.

#include "RemoteExecutor.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

struct PXMethod { const char* name; uint32_t id; int argType; };

static const PXMethod g_Methods[] = {
    {"Start",1091,0}, {"Stop",1090,0}, {"ForceStart",1089,0}, {"Kill",1095,0},
    {"Delete",1237,0}, {"ActionStart",1083,-1}, {"ActionStop",1084,-1},
    {"AddPosition",1031,7}, {"Move",1240,32}, {"SetOrientationByObject",1036,32},
    {"GetActorPositionWSX",1338,3}, {"GetActorPositionWSY",1339,3}, {"GetActorPositionWSZ",1340,3},
    {"Position",1019,-1},
    {"AddViewText",40117,4}, {"SetViewText",40102,4}, {"ViewText",40102,4},
    {"ViewTranslateText",40122,14},
    {"SetViewTextByTimeMinSec",40113,3}, {"SetViewTextByTimeMinSecHun",40115,3},
    {"AddViewTextFloat",40118,3}, {"AddViewTextInt",40119,1}, {"AddViewTextUInt",40120,2},
    {"SetViewTextFromDataSource",40121,4},
    {"SetSkyModifierSkyColor",83050,10}, {"SetSkyModifierHorizonColor",83052,10},
    {"SetSkyModifierColorMix",83074,3}, {"StartSkyModifier",83112,-1},
    {"SetWorldDrawGlobalSpace",26004,1},
    {"QuestComplete",123031,0}, {"QuestPlayerLevelChangeNotify",123243,0},
    {"QuestManagerCompleteSelected",154004,0}, {"QuestManagerDiscardSelected",154007,0},
    {"QuestManagerSetQuestAvailable",154011,-1}, {"QuestManagerSetQuestActive",154012,-1},
    {"QuestManagerSetQuestConditionsCompleted",154013,-1}, {"QuestManagerSetQuestComplete",154014,-1},
    {"QuestManagerSetQuestFail",154015,-1},
    {"QuestManagerMoveToQuestGiver",154017,-1}, {"QuestManagerMoveToQuestReceiver",154018,-1},
    {"DiscardQuest",0x25997,0}, {"HorseCare",0x1DCE3,0},
    {"NetworkChristmasHack",122085,0},
    {"NetworkDebugAddXP",122086,-1}, {"NetworkDebugAddHorseXP",122087,-1},
    {"NetworkDebugResetHorseLevel",122088,0},
    {"NetworkDebugAddMoney",122089,-1}, {"NetworkDebugAddStarMoney",122090,-1},
    {"NetworkDebugResetStarMoney",122091,-1},
    {"NetworkHorseFreeWellbeing",122083,0}, {"HorseRequestLevelUp",120147,0},
    {"HorseStartCallHorseTeleportSetup",120137,0},
    {"HorseMaxFallTime",120266,3}, {"PlayerTPNetMaxFallTime",226166,3},
    {"HorseRestoreAppearance",120170,0}, {"HorseAppearanceNormal",120171,0},
    {"HorseAppearanceCustomBody",120173,31}, {"HorseAppearanceCustomHair",120174,31},
    {"CloneHorseAppearance",120180,-1}, {"CloneHorse",167002,-1},
    {"HorseForSaleStartBuyWindow",167007,0},
    {"FileObjectLoad",36000,0},
    {"FactionAddReputation",156008,-1}, {"FactionSetReputation",156022,-1},
    {"ShopOpen",161016,0},
    {"PlayerTPNetPlayAnimation",226080,4}, {"PlayerTPNetPlayAnimationLooping",226083,4},
    {"PlayerTPNetPlayAnimationEnd",226085,0},
    {"RunScript",1209,4}, {"GetPropertyValueAsString",1223,4},
};

static RemoteExecutor rex;
static uint64_t g_FindActorAddr = 0;
static uint64_t g_ExtractAddr   = 0;
static uint64_t g_RegistryAddr  = 0;
static uint64_t g_CtxOffset     = 0x190;

// user data layout (relative to rex.Data())
static constexpr size_t SSO_OUTPUT     = 0x000;
static constexpr size_t SSO_CONTEXT    = 0x010;
static constexpr size_t SSO_LOCAL      = 0x020;
static constexpr size_t SSO_SLOT       = 0x030;
static constexpr size_t SSO_CONSUMED   = 0x040;
static constexpr size_t SSO_FLAGS      = 0x044;
static constexpr size_t SSO_SCENEROOT  = 0x048;
static constexpr size_t SSO_PATH       = 0x050;
static constexpr size_t SSO_ACTOR      = 0x250;
static constexpr size_t SSO_VTB8       = 0x258;
static constexpr size_t SSO_RESULT     = 0x260;
static constexpr size_t SSO_ARGS       = 0x268;
static constexpr size_t SSO_EXTRA      = 0x1268;
static constexpr size_t SSO_VT8_CTX    = 0x2268;
static constexpr size_t SSO_VT8_CMDID  = 0x2270;
static constexpr size_t SSO_OUTPUT2    = 0x2280;
static constexpr size_t SSO_PATH2      = 0x2290;

static constexpr uint32_t INVALID_INDEX = 0x0BADF00D;

#define AX(v) (unsigned long long)(v)

// asm helpers — build shellcode strings for Keystone

static int AsmResolveActor(char* buf, int n, size_t sz,
    uint64_t addrOutput, uint64_t addrPath, uint64_t addrActorOut, uint64_t addrVTB8Out)
{
    #define A(...) n += snprintf(buf + n, sz - n, __VA_ARGS__)
    A("sub rsp, 0x68; ");
    A("mov rax, 0x%llX; mov rcx, [rax]; ", AX(g_RegistryAddr));
    A("mov rdx, 0x%llX; ",  AX(addrOutput));
    A("mov r8, 0x%llX; ",   AX(rex.Data(SSO_CONTEXT)));
    A("mov r9, 0x%llX; ",   AX(addrPath));
    A("mov rax, 0x%llX; mov [rsp+0x20], rax; ", AX(rex.Data(SSO_LOCAL)));
    A("mov rax, 0x%llX; mov [rsp+0x28], rax; ", AX(rex.Data(SSO_SLOT)));
    A("mov rax, 0x%llX; mov [rsp+0x30], rax; ", AX(rex.Data(SSO_CONSUMED)));
    A("mov qword ptr [rsp+0x38], 0; ");
    A("mov qword ptr [rsp+0x40], 0; ");
    A("mov rax, 0x%llX; call rax; ", AX(g_FindActorAddr));
    A("add rsp, 0x68; ");
    A("mov rax, 0x%llX; mov eax, [rax]; ", AX(addrOutput + 12));
    A("cmp eax, 0x0BADF00D; je error; ");
    A("sub rsp, 0x28; ");
    A("mov rcx, 0x%llX; ",  AX(addrOutput));
    A("mov rax, 0x%llX; call rax; ", AX(g_ExtractAddr));
    A("mov rcx, 0x%llX; mov [rcx], rax; ", AX(addrActorOut));
    A("add rsp, 0x28; ");
    A("mov rax, 0x%llX; mov rax, [rax]; mov rax, [rax]; mov rax, [rax+0x40]; ", AX(addrActorOut));
    A("mov rcx, 0x%llX; mov [rcx], rax; ", AX(addrVTB8Out));
    #undef A
    return n;
}

static int AsmVtable8Call(char* buf, int n, size_t sz,
    uint64_t addrActor, uint64_t addrCtx, uint64_t addrCmdId,
    uint64_t addrArgs, uint64_t addrExtra, uint64_t addrVTB8, uint64_t addrResult)
{
    #define A(...) n += snprintf(buf + n, sz - n, __VA_ARGS__)
    A("sub rsp, 0x38; ");
    A("mov rax, 0x%llX; mov rcx, [rax]; ", AX(addrActor));
    A("mov rax, 0x%llX; mov rdx, [rax]; ", AX(addrCtx));
    A("mov rax, 0x%llX; mov r8d, [rax]; ", AX(addrCmdId));
    A("mov r9, 0x%llX; ",  AX(addrArgs));
    A("mov rax, 0x%llX; mov [rsp+0x20], rax; ", AX(addrExtra));
    A("mov rax, 0x%llX; mov rax, [rax]; call rax; ", AX(addrVTB8));
    A("mov rcx, 0x%llX; mov [rcx], rax; ", AX(addrResult));
    A("add rsp, 0x38; ");
    #undef A
    return n;
}

static int AsmDoneError(char* buf, int n, size_t sz)
{
    #define A(...) n += snprintf(buf + n, sz - n, __VA_ARGS__)
    A("mov rax, 0x%llX; mov byte ptr [rax], 0; ", AX(rex.cave + rex.offError));
    A("mov rax, 0x%llX; mov byte ptr [rax], 0; ", AX(rex.cave + rex.offRequest));
    A("mov rax, 0x%llX; mov byte ptr [rax], 1; ret; ", AX(rex.cave + rex.offDone));
    A("error: ");
    A("mov rax, 0x%llX; mov byte ptr [rax], 1; ", AX(rex.cave + rex.offError));
    A("mov rax, 0x%llX; mov byte ptr [rax], 0; ", AX(rex.cave + rex.offRequest));
    A("mov rax, 0x%llX; mov byte ptr [rax], 1; ret", AX(rex.cave + rex.offDone));
    #undef A
    return n;
}

// payload builders

static void BuildResolveAndCallPayload()
{
    char buf[8192]; int n = 0;
    n = AsmResolveActor(buf, n, sizeof(buf),
        rex.Data(SSO_OUTPUT), rex.Data(SSO_PATH), rex.Data(SSO_ACTOR), rex.Data(SSO_VTB8));
    n = AsmVtable8Call(buf, n, sizeof(buf),
        rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_VT8_CMDID),
        rex.Data(SSO_ARGS), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
    n = AsmDoneError(buf, n, sizeof(buf));
    Payload pl; pl.Asm(buf);
    rex.WriteCode(pl.code, pl.len);
}

static void BuildCompoundPayload()
{
    char buf[12288]; int n = 0;
    n = AsmResolveActor(buf, n, sizeof(buf),
        rex.Data(SSO_OUTPUT), rex.Data(SSO_PATH), rex.Data(SSO_ACTOR), rex.Data(SSO_VTB8));
    n = AsmVtable8Call(buf, n, sizeof(buf),
        rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_OUTPUT2),
        rex.Data(SSO_PATH2), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
    n = AsmVtable8Call(buf, n, sizeof(buf),
        rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_VT8_CMDID),
        rex.Data(SSO_ARGS), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
    n = AsmDoneError(buf, n, sizeof(buf));
    Payload pl; pl.Asm(buf);
    rex.WriteCode(pl.code, pl.len);
}

static void BuildArgType32Payload()
{
    char buf[16384]; int n = 0;
    #define A(...) n += snprintf(buf + n, sizeof(buf) - n, __VA_ARGS__)

    n = AsmResolveActor(buf, n, sizeof(buf),
        rex.Data(SSO_OUTPUT), rex.Data(SSO_PATH), rex.Data(SSO_ACTOR), rex.Data(SSO_VTB8));

    // second FindActorByPath for arg actor
    A("sub rsp, 0x68; ");
    A("mov rax, 0x%llX; mov rcx, [rax]; ", AX(g_RegistryAddr));
    A("mov rdx, 0x%llX; ",  AX(rex.Data(SSO_OUTPUT2)));
    A("mov r8, 0x%llX; ",   AX(rex.Data(SSO_CONTEXT)));
    A("mov r9, 0x%llX; ",   AX(rex.Data(SSO_PATH2)));
    A("mov rax, 0x%llX; mov [rsp+0x20], rax; ", AX(rex.Data(SSO_LOCAL)));
    A("mov rax, 0x%llX; mov [rsp+0x28], rax; ", AX(rex.Data(SSO_SLOT)));
    A("mov rax, 0x%llX; mov [rsp+0x30], rax; ", AX(rex.Data(SSO_CONSUMED)));
    A("mov qword ptr [rsp+0x38], 0; ");
    A("mov qword ptr [rsp+0x40], 0; ");
    A("mov rax, 0x%llX; call rax; ", AX(g_FindActorAddr));
    A("add rsp, 0x68; ");
    A("mov rax, 0x%llX; mov eax, [rax]; ", AX(rex.Data(SSO_OUTPUT2) + 12));
    A("cmp eax, 0x0BADF00D; je error; ");

    // copy SafeActorPtr (16 bytes) from OUTPUT2 to ARGS
    A("mov rax, 0x%llX; ", AX(rex.Data(SSO_OUTPUT2)));
    A("mov rcx, [rax]; mov r8, [rax+0x08]; ");
    A("mov rax, 0x%llX; ", AX(rex.Data(SSO_ARGS)));
    A("mov [rax], rcx; mov [rax+0x08], r8; ");
    #undef A

    n = AsmVtable8Call(buf, n, sizeof(buf),
        rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_VT8_CMDID),
        rex.Data(SSO_ARGS), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
    n = AsmDoneError(buf, n, sizeof(buf));
    Payload pl; pl.Asm(buf);
    rex.WriteCode(pl.code, pl.len);
}

// cave data init

static void InitCaveData()
{
    uint8_t nullSafe[16] = {};
    uint32_t badIdx = INVALID_INDEX;
    memcpy(nullSafe + 12, &badIdx, 4);
    rex.WPM(rex.Data(SSO_OUTPUT), nullSafe, 16);
    rex.WPM(rex.Data(SSO_CONTEXT), nullSafe, 16);
    rex.WPM(rex.Data(SSO_LOCAL), nullSafe, 16);
    rex.WPM(rex.Data(SSO_SLOT), nullSafe, 16);
}

static void PrepareResolveData(const char* path)
{
    uint8_t nullSafe[16] = {};
    uint32_t badIdx = INVALID_INDEX;
    memcpy(nullSafe + 12, &badIdx, 4);
    rex.WPM(rex.Data(SSO_OUTPUT), nullSafe, 16);

    char pathBuf[512] = {};
    strncpy(pathBuf, path, 511);
    rex.WPM(rex.Data(SSO_PATH), pathBuf, 512);

    uint8_t zero8[8] = {};
    rex.WPM(rex.Data(SSO_CONSUMED), zero8, 4);
    rex.WPM(rex.Data(SSO_FLAGS), zero8, 4);
    rex.WPM(rex.Data(SSO_SCENEROOT), zero8, 8);
}

// execution

static bool TriggerAndWait()
{
    uint64_t regPtr = rex.ReadVal<uint64_t>(g_RegistryAddr);
    uint64_t ctx = regPtr ? rex.ReadVal<uint64_t>(regPtr + g_CtxOffset) : 0;
    rex.WPM(rex.Data(SSO_VT8_CTX), &ctx, 8);

    rex.Trigger();
    if (!rex.WaitDone()) return false;
    if (rex.HadError()) { printf("[!] actor not found\n"); return false; }

    int64_t result = rex.ReadVal<int64_t>(rex.Data(SSO_RESULT));
    printf("[+] vtable[8] ret = %lld\n", (long long)result);
    return true;
}

static bool RemoteCallVtable8(const char* actorPath, uint32_t cmdId)
{
    PrepareResolveData(actorPath);
    rex.WPM(rex.Data(SSO_VT8_CMDID), &cmdId, 4);
    BuildResolveAndCallPayload();
    return TriggerAndWait();
}

static bool RemoteCallCompound(const char* actorPath, uint32_t cmdId1, const void* args1, size_t args1Len, uint32_t cmdId2)
{
    PrepareResolveData(actorPath);
    rex.WPM(rex.Data(SSO_VT8_CMDID), &cmdId2, 4);
    rex.WPM(rex.Data(SSO_OUTPUT2), &cmdId1, 4);
    uint8_t compArgs[512] = {};
    if (args1 && args1Len) memcpy(compArgs, args1, args1Len < 512 ? args1Len : 512);
    rex.WPM(rex.Data(SSO_PATH2), compArgs, 512);
    BuildCompoundPayload();
    return TriggerAndWait();
}

static bool RemoteCallArgType32(const char* mainPath, const char* argActorPath, uint32_t cmdId)
{
    PrepareResolveData(mainPath);
    rex.WPM(rex.Data(SSO_VT8_CMDID), &cmdId, 4);

    uint8_t nullSafe2[16] = {};
    uint32_t badIdx = INVALID_INDEX;
    memcpy(nullSafe2 + 12, &badIdx, 4);
    rex.WPM(rex.Data(SSO_OUTPUT2), nullSafe2, 16);

    char pathBuf2[512] = {};
    strncpy(pathBuf2, argActorPath, 511);
    rex.WPM(rex.Data(SSO_PATH2), pathBuf2, 512);

    BuildArgType32Payload();
    return TriggerAndWait();
}

// script parser

struct ScriptArg { bool isStr; char str[256]; uint64_t num; bool isFloat; };

static const PXMethod* LookupMethod(const char* name) {
    for (auto& m : g_Methods)
        if (strcmp(m.name, name) == 0) return &m;
    return nullptr;
}

static float ArgToFloat(const ScriptArg& a) {
    if (a.isFloat) { uint32_t b = (uint32_t)a.num; float f; memcpy(&f, &b, 4); return f; }
    return (float)(int64_t)a.num;
}

static void WriteSSOString(uint64_t argsAddr, const char* s) {
    uint8_t argsBuf[4096] = {};
    size_t len = strlen(s);
    if (len <= 15) {
        memcpy(argsBuf, s, len);
        uint64_t slen = len, cap = 15;
        memcpy(argsBuf + 16, &slen, 8);
        memcpy(argsBuf + 24, &cap, 8);
    } else {
        if (len > 250) len = 250;
        uintptr_t rem = (uintptr_t)VirtualAllocEx(rex.proc, nullptr, len + 1,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rem) { printf("[!] heap alloc failed\n"); return; }
        char tmp[256] = {};
        memcpy(tmp, s, len);
        rex.WPM(rem, tmp, len + 1);
        memcpy(argsBuf, &rem, 8);
        uint64_t slen = len;
        memcpy(argsBuf + 16, &slen, 8);
        memcpy(argsBuf + 24, &slen, 8);
    }
    rex.WPM(argsAddr, argsBuf, sizeof(argsBuf));
}

static bool RunStatement(const char* defaultActor, const char* stmt)
{
    const char* paren = strchr(stmt, '(');
    if (!paren) { printf("[!] missing '('\n"); return false; }
    const char* close = strrchr(stmt, ')');
    if (!close) { printf("[!] missing ')'\n"); return false; }

    // find last dot before paren
    const char* dot = nullptr;
    for (const char* p = paren - 1; p >= stmt; --p)
        if (*p == '.') { dot = p; break; }
    if (!dot) { printf("[!] expected path.Method(...)\n"); return false; }

    char path[256] = {}, method[128] = {}, argStr[1024] = {};
    size_t pathLen = dot - stmt;
    if (pathLen >= sizeof(path)) pathLen = sizeof(path) - 1;
    memcpy(path, stmt, pathLen);

    size_t methLen = paren - dot - 1;
    if (methLen >= sizeof(method)) methLen = sizeof(method) - 1;
    memcpy(method, dot + 1, methLen);

    size_t argLen = close - paren - 1;
    if (argLen >= sizeof(argStr)) argLen = sizeof(argStr) - 1;
    memcpy(argStr, paren + 1, argLen);

    const char* usePath = (strcmp(path, "this") == 0) ? defaultActor : path;

    uint32_t cmdId = 0;
    int argType = -1;

    if (method[0] == '#') {
        cmdId = (uint32_t)strtoul(method + 1, nullptr, 0);
        if (!cmdId) { printf("[!] invalid #ID\n"); return false; }
    } else {
        auto* m = LookupMethod(method);
        if (!m) {
            // unknown method -> RunScript fallback
            printf("[*] unknown '%s' -> RunScript\n", method);
            cmdId = 1209; argType = 4;
            char runBuf[512];
            snprintf(runBuf, sizeof(runBuf), "this.%s%s", method, paren);
            WriteSSOString(rex.Data(SSO_ARGS), runBuf);
            uint8_t extraBuf[4096] = {};
            rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
            bool ok = RemoteCallVtable8(usePath, cmdId);
            // free remote heap if allocated
            uint64_t rs = rex.ReadVal<uint64_t>(rex.Data(SSO_ARGS));
            if (rs != 0) VirtualFreeEx(rex.proc, (LPVOID)rs, 0, MEM_RELEASE);
            return ok;
        }
        cmdId = m->id;
        argType = m->argType;
    }

    // parse args
    std::vector<ScriptArg> args;
    {
        const char* p = argStr;
        while (*p && args.size() < 4) {
            while (*p == ' ') p++;
            if (!*p) break;
            ScriptArg a = {};
            if (*p == '"') {
                p++;
                a.isStr = true;
                int i = 0;
                while (*p && *p != '"' && i < 255) {
                    if (*p == '\\' && *(p+1)) { p++; a.str[i++] = (*p == 'n') ? '\n' : (*p == 't') ? '\t' : *p; p++; }
                    else a.str[i++] = *p++;
                }
                if (*p == '"') p++;
            } else {
                int i = 0;
                while (*p && *p != ',' && i < 255) a.str[i++] = *p++;
                // trim trailing spaces
                while (i > 0 && a.str[i-1] == ' ') i--;
                a.str[i] = 0;
                bool isNum = (a.str[0] >= '0' && a.str[0] <= '9') || a.str[0] == '-' || a.str[0] == '+' || a.str[0] == '.';
                if (!isNum) { a.isStr = true; }
                else {
                    a.isFloat = (strchr(a.str, '.') || strchr(a.str, 'e') || strchr(a.str, 'E')) != nullptr;
                    if (a.isFloat) {
                        float f = strtof(a.str, nullptr);
                        uint32_t bits; memcpy(&bits, &f, 4);
                        a.num = bits;
                    } else {
                        a.num = strtoull(a.str, nullptr, 0);
                    }
                    a.isStr = false;
                }
            }
            args.push_back(a);
            while (*p == ' ') p++;
            if (*p == ',') p++;
        }
    }

    // marshal args
    uint8_t argsBuf[4096] = {};
    uint8_t extraBuf[4096] = {};
    uintptr_t remHeap = 0;

    if (argType == 4) {
        const char* s = (args.size() >= 1 && args[0].isStr) ? args[0].str : "";
        WriteSSOString(rex.Data(SSO_ARGS), s);
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    } else if (argType == 7) {
        for (int i = 0; i < 3; i++) {
            float f = (i < (int)args.size() && !args[i].isStr) ? ArgToFloat(args[i]) : 0.f;
            memcpy(argsBuf + i * 4, &f, 4);
        }
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    } else if (argType == 1 || argType == 2 || argType == 3 || argType == 14) {
        if (args.size() >= 1 && !args[0].isStr) {
            if (argType == 3 && !args[0].isFloat) {
                float f = ArgToFloat(args[0]);
                uint32_t bits; memcpy(&bits, &f, 4);
                uint64_t v = bits;
                memcpy(argsBuf, &v, 8);
            } else {
                memcpy(argsBuf, &args[0].num, 8);
            }
        }
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    } else if (argType == 10) {
        for (int i = 0; i < 4; i++) {
            float f = (i < (int)args.size() && !args[i].isStr) ? ArgToFloat(args[i]) : 0.f;
            memcpy(argsBuf + i * 4, &f, 4);
        }
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    } else if (argType == 31) {
        for (int i = 0; i < (int)args.size(); i++) {
            uint32_t v = args[i].isFloat ? (uint32_t)ArgToFloat(args[i]) : (uint32_t)args[i].num;
            memcpy(argsBuf + i * 4, &v, 4);
        }
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    } else if (argType == 32) {
        const char* argActorPath = (args.size() >= 1 && args[0].isStr) ? args[0].str : defaultActor;
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
        return RemoteCallArgType32(usePath, argActorPath, cmdId);
    } else if (argType == 0) {
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    } else {
        if (args.size() == 1 && !args[0].isStr)
            memcpy(argsBuf, &args[0].num, 8);
        else if (args.size() > 1) {
            bool hasFloat = false;
            for (auto& a : args) if (a.isFloat) hasFloat = true;
            if (hasFloat)
                for (int i = 0; i < (int)args.size(); i++) { float f = ArgToFloat(args[i]); memcpy(argsBuf + i * 4, &f, 4); }
            else
                for (int i = 0; i < (int)args.size(); i++) { uint32_t v = (uint32_t)args[i].num; memcpy(argsBuf + i * 4, &v, 4); }
        }
        rex.WPM(rex.Data(SSO_ARGS), argsBuf, sizeof(argsBuf));
        rex.WPM(rex.Data(SSO_EXTRA), extraBuf, sizeof(extraBuf));
    }

    // compound: ViewText triggers ViewTranslateText(1) first
    if (cmdId == 40102) {
        uint32_t flag = 1;
        return RemoteCallCompound(usePath, 40122, &flag, 4, cmdId);
    }

    bool ret = RemoteCallVtable8(usePath, cmdId);
    if (remHeap) VirtualFreeEx(rex.proc, (LPVOID)remHeap, 0, MEM_RELEASE);
    return ret;
}

static void RunPXScript(const char* defaultActor, const char* script)
{
    char buf[4096];
    strncpy(buf, script, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* ctx = nullptr;
    char* tok = strtok_s(buf, ";", &ctx);
    while (tok) {
        while (*tok == ' ') tok++;
        if (*tok) {
            printf("\n>>> %s\n", tok);
            RunStatement(defaultActor, tok);
        }
        tok = strtok_s(nullptr, ";", &ctx);
    }
}

int main(int argc, char** argv)
{
    if (argc < 4) {
        printf("Usage: %s <ExtractActor_RVA> <FindActorByPath_RVA> <Registry_RVA> [CtxOffset]\n", argv[0]);
        printf("  All values in hex (0x prefix optional)\n");
        printf("  Example: %s 0x1A2B30 0x3C4D50 0x5E6F70\n", argv[0]);
        return 1;
    }

    uint64_t extractRVA = strtoull(argv[1], nullptr, 16);
    uint64_t findRVA    = strtoull(argv[2], nullptr, 16);
    uint64_t regRVA     = strtoull(argv[3], nullptr, 16);
    if (argc >= 5) g_CtxOffset = strtoull(argv[4], nullptr, 16);

    printf("=== SSOExternal PoC ===\n");
    if (!rex.Attach("SSOClient.exe", 300)) return 1;

    g_ExtractAddr   = rex.base + extractRVA;
    g_FindActorAddr = rex.base + findRVA;
    g_RegistryAddr  = rex.base + regRVA;

    printf("[*] ExtractActor:    0x%llX\n", AX(g_ExtractAddr));
    printf("[*] FindActorByPath: 0x%llX\n", AX(g_FindActorAddr));
    printf("[*] Registry:        0x%llX\n", AX(g_RegistryAddr));
    printf("[*] CtxOffset:       0x%llX\n", AX(g_CtxOffset));

    // wait for registry to be populated
    printf("[*] waiting for registry...\n");
    uint64_t regPtr = 0;
    for (int i = 0; i < 300 && !regPtr; i++) {
        regPtr = rex.ReadVal<uint64_t>(g_RegistryAddr);
        if (!regPtr) Sleep(100);
    }
    if (!regPtr) printf("[!] registry stayed NULL\n");
    else printf("[+] registry: 0x%llX\n", AX(regPtr));

    if (!rex.AllocCave()) { rex.Cleanup(); return 1; }
    InitCaveData();

    if (!rex.InstallHook()) { printf("[!] hook failed\n"); rex.Cleanup(); return 1; }

    printf("\nready. syntax: @actor path.Method(args);...\n");
    printf("  default actor: global/Horse\n");
    printf("  quit/exit to stop\n\n");

    char line[4096];
    while (true) {
        printf("> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (!len) continue;
        if (_stricmp(line, "quit") == 0 || _stricmp(line, "exit") == 0) break;
        if (!rex.IsAlive()) { printf("[!] target exited\n"); break; }

        const char* actor = "global/Horse";
        const char* script = line;
        if (line[0] == '@') {
            char* sp = strchr(line + 1, ' ');
            if (sp) { *sp = 0; actor = line + 1; script = sp + 1; }
        }
        RunPXScript(actor, script);
    }

    rex.Cleanup();
    printf("bye.\n");
    return 0;
}
