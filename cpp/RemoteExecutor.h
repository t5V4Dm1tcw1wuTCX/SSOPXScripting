// RemoteExecutor.h — IAT hook + code-cave remote execution (x64)
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <keystone/keystone.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

struct Payload {
    uint8_t code[4096] = {};
    int len = 0;

    bool Asm(const char* asmCode, uint64_t address = 0) {
        ks_engine* ks = nullptr;
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
            printf("[!] ks_open failed\n");
            return false;
        }
        unsigned char* enc = nullptr;
        size_t sz = 0, cnt = 0;
        int ret = ks_asm(ks, asmCode, address, &enc, &sz, &cnt);
        if (ret == 0 && sz > 0) {
            memcpy(code + len, enc, sz);
            len += (int)sz;
        } else {
            printf("[!] ks_asm: %s\n", ks_strerror(ks_errno(ks)));
        }
        if (enc) ks_free(enc);
        ks_close(ks);
        return ret == 0;
    }
};

struct RemoteExecutor {
    HANDLE proc = nullptr;
    uintptr_t base = 0;
    size_t moduleSize = 0;
    DWORD pid = 0;
    DWORD mainThreadId = 0;

    uintptr_t cave = 0;
    size_t caveSize = 0;

    // cave layout
    size_t offDone       = 0x00;
    size_t offRequest    = 0x01;
    size_t offError      = 0x02;
    size_t offOrigFunc   = 0x08;
    size_t offIATAddr    = 0x10;
    size_t offUserData   = 0x20;
    size_t offCode       = 0x2800;
    size_t offTrampoline = 0x3800;

    bool iatHooked = false;
    uintptr_t iatEntryAddr = 0;
    uintptr_t origFuncAddr = 0;

    bool Attach(const char* exeName, int timeoutSec = 60) {
        for (int i = 0; i < timeoutSec && !pid; ++i) {
            pid = FindPID(exeName);
            if (!pid) Sleep(1000);
        }
        if (!pid) { printf("[!] '%s' not found\n", exeName); return false; }
        printf("[*] PID: %lu\n", pid);

        proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!proc) { printf("[!] OpenProcess: %lu\n", GetLastError()); return false; }

        if (!GetModInfo(pid, exeName, &base, &moduleSize)) {
            printf("[!] module info failed\n"); return false;
        }
        printf("[*] Base: 0x%llX  Size: 0x%zX\n", (unsigned long long)base, moduleSize);

        mainThreadId = FindMainThread(pid);
        if (!mainThreadId) { printf("[!] main thread not found\n"); return false; }
        printf("[*] MainThread: %lu\n", mainThreadId);
        return true;
    }

    bool RPM(uintptr_t addr, void* buf, size_t len) const {
        SIZE_T rd = 0;
        return ReadProcessMemory(proc, (LPCVOID)addr, buf, len, &rd) && rd == len;
    }
    bool WPM(uintptr_t addr, const void* buf, size_t len) const {
        SIZE_T wr = 0;
        return WriteProcessMemory(proc, (LPVOID)addr, buf, len, &wr) && wr == len;
    }
    template<typename T> T ReadVal(uintptr_t addr) const {
        T v{}; RPM(addr, &v, sizeof(T)); return v;
    }

    uintptr_t Data(size_t offset = 0) const { return cave + offUserData + offset; }
    uintptr_t Code() const { return cave + offCode; }

    bool AllocCave(size_t size = 0x4000) {
        caveSize = size;
        cave = (uintptr_t)VirtualAllocEx(proc, nullptr, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cave) { printf("[!] VirtualAllocEx failed\n"); return false; }
        std::vector<uint8_t> z(size, 0);
        WPM(cave, z.data(), z.size());
        printf("[*] Cave: 0x%llX (%zu bytes)\n", (unsigned long long)cave, size);
        return true;
    }

    void FreeCave() {
        if (cave) { VirtualFreeEx(proc, (LPVOID)cave, 0, MEM_RELEASE); cave = 0; }
    }

    bool FindIATEntry(const char* dllName, const char* funcName,
                      uintptr_t* outIAT, uintptr_t* outOrig) const {
        uint16_t magic = 0; RPM(base, &magic, 2);
        if (magic != 0x5A4D) return false;
        int32_t e_lfanew = 0; RPM(base + 0x3C, &e_lfanew, 4);
        uintptr_t pe = base + e_lfanew;
        uint32_t sig = 0; RPM(pe, &sig, 4);
        if (sig != 0x4550) return false;
        uint32_t importRVA = 0;
        RPM(pe + 0x90, &importRVA, 4);
        if (!importRVA) return false;
        uintptr_t imp = base + importRVA;
        for (int i = 0; i < 512; ++i) {
            uint32_t f[5] = {}; RPM(imp + i * 20, f, 20);
            if (!f[3] && !f[4]) break;
            char name[64] = {}; RPM(base + f[3], name, 63);
            if (_stricmp(name, dllName) != 0) continue;
            uint32_t oft = f[0] ? f[0] : f[4];
            for (int j = 0; j < 4096; ++j) {
                uint64_t ot = 0, it = 0;
                RPM(base + oft + j * 8, &ot, 8);
                RPM(base + f[4] + j * 8, &it, 8);
                if (!ot) break;
                if (ot & (1ULL << 63)) continue;
                char fn[128] = {}; RPM(base + (uint32_t)ot + 2, fn, 127);
                if (strcmp(fn, funcName) == 0) {
                    *outIAT = base + f[4] + j * 8;
                    *outOrig = it;
                    return true;
                }
            }
        }
        return false;
    }

    bool InstallHook() {
        struct { const char* dll; const char* func; } targets[] = {
            { "USER32.dll", "TranslateMessage" },
            { "USER32.dll", "PeekMessageW" },
            { "USER32.dll", "DispatchMessageW" },
            { "USER32.dll", "GetMessageW" },
            { "KERNEL32.dll", "GetTickCount64" },
            { "KERNEL32.dll", "QueryPerformanceCounter" },
        };
        for (auto& t : targets) {
            uintptr_t iat = 0, orig = 0;
            if (FindIATEntry(t.dll, t.func, &iat, &orig)) {
                printf("[*] Hook: %s!%s @ 0x%llX\n", t.dll, t.func, (unsigned long long)iat);
                return DoInstallHook(iat, orig);
            }
        }
        printf("[!] no suitable IAT entry\n");
        return false;
    }

    void UninstallHook() {
        if (!iatHooked) return;
        DWORD oldProt = 0;
        VirtualProtectEx(proc, (LPVOID)iatEntryAddr, 8, PAGE_READWRITE, &oldProt);
        WPM(iatEntryAddr, &origFuncAddr, 8);
        VirtualProtectEx(proc, (LPVOID)iatEntryAddr, 8, oldProt, &oldProt);
        iatHooked = false;
    }

    void WriteCode(const void* code, size_t len) { WPM(cave + offCode, code, len); }

    void Trigger() {
        uint8_t zero = 0, one = 1;
        WPM(cave + offDone, &zero, 1);
        WPM(cave + offError, &zero, 1);
        WPM(cave + offRequest, &one, 1);
    }

    bool WaitDone(int timeoutMs = 5000) {
        for (int i = 0; i < timeoutMs; ++i) {
            uint8_t done = 0;
            RPM(cave + offDone, &done, 1);
            if (done) return true;
            Sleep(1);
        }
        uint8_t zero = 0;
        WPM(cave + offRequest, &zero, 1);
        printf("[!] timeout (%dms)\n", timeoutMs);
        return false;
    }

    bool HadError() const {
        uint8_t err = 0;
        const_cast<RemoteExecutor*>(this)->RPM(cave + offError, &err, 1);
        return err != 0;
    }

    bool Execute(const Payload& pl, int timeoutMs = 5000) {
        WriteCode(pl.code, pl.len);
        Trigger();
        return WaitDone(timeoutMs);
    }

    void Cleanup() {
        UninstallHook();
        FreeCave();
        if (proc) { CloseHandle(proc); proc = nullptr; }
    }

    bool IsAlive() const {
        DWORD exitCode = 0;
        return GetExitCodeProcess(proc, &exitCode) && exitCode == STILL_ACTIVE;
    }

private:
    bool DoInstallHook(uintptr_t iat, uintptr_t orig) {
        iatEntryAddr = iat;
        origFuncAddr = orig;
        WPM(cave + offOrigFunc, &orig, 8);
        WPM(cave + offIATAddr, &iat, 8);
        BuildTrampoline();
        uintptr_t tramp = cave + offTrampoline;
        DWORD oldProt = 0;
        VirtualProtectEx(proc, (LPVOID)iat, 8, PAGE_READWRITE, &oldProt);
        WPM(iat, &tramp, 8);
        VirtualProtectEx(proc, (LPVOID)iat, 8, oldProt, &oldProt);
        iatHooked = true;
        printf("[+] hook installed\n");
        return true;
    }

    static DWORD FindPID(const char* name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        DWORD pid = 0;
        if (Process32First(snap, &pe)) {
            do { if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        return pid;
    }

    static bool GetModInfo(DWORD pid, const char* mod, uintptr_t* b, size_t* s) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32 me{}; me.dwSize = sizeof(me);
        bool ok = false;
        if (Module32First(snap, &me)) {
            do { if (_stricmp(me.szModule, mod) == 0) {
                *b = (uintptr_t)me.modBaseAddr; *s = me.modBaseSize; ok = true; break;
            } } while (Module32Next(snap, &me));
        }
        CloseHandle(snap);
        return ok;
    }

    static DWORD FindMainThread(DWORD pid) {
        for (int i = 0; i < 50; ++i) {
            HWND hwnd = nullptr;
            HWND found = nullptr;
            while ((hwnd = FindWindowExA(nullptr, hwnd, nullptr, nullptr)) != nullptr) {
                DWORD wndPid = 0;
                GetWindowThreadProcessId(hwnd, &wndPid);
                if (wndPid == pid && IsWindowVisible(hwnd)) {
                    found = hwnd;
                    char cls[64] = {};
                    GetClassNameA(hwnd, cls, sizeof(cls));
                    if (strstr(cls, "UnrealWindow") || strstr(cls, "Win32"))
                        return GetWindowThreadProcessId(hwnd, nullptr);
                }
            }
            if (found) return GetWindowThreadProcessId(found, nullptr);
            Sleep(200);
        }
        return 0;
    }

    void BuildTrampoline() {
        uint64_t aReq  = cave + offRequest;
        uint64_t aOrig = cave + offOrigFunc;
        uint64_t aCode = cave + offCode;

        char buf[2048];
        snprintf(buf, sizeof(buf),
            "push rax; "
            "mov rax, 0x%llX; cmp byte ptr [rax], 0; "
            "pop rax; "
            "je skip; "
            "push rcx; push rdx; push r8; push r9; push r10; push r11; "
            "sub rsp, 0x68; "
            "movups [rsp], xmm0; movups [rsp+0x10], xmm1; "
            "movups [rsp+0x20], xmm2; movups [rsp+0x30], xmm3; "
            "movups [rsp+0x40], xmm4; movups [rsp+0x50], xmm5; "
            "mov rax, 0x%llX; call rax; "
            "movups xmm0, [rsp]; movups xmm1, [rsp+0x10]; "
            "movups xmm2, [rsp+0x20]; movups xmm3, [rsp+0x30]; "
            "movups xmm4, [rsp+0x40]; movups xmm5, [rsp+0x50]; "
            "add rsp, 0x68; "
            "pop r11; pop r10; pop r9; pop r8; pop rdx; pop rcx; "
            "skip: "
            "mov rax, 0x%llX; mov rax, [rax]; jmp rax",
            (unsigned long long)aReq,
            (unsigned long long)aCode,
            (unsigned long long)aOrig);

        ks_engine* ks = nullptr;
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) return;
        unsigned char* enc = nullptr;
        size_t sz = 0, cnt = 0;
        if (ks_asm(ks, buf, 0, &enc, &sz, &cnt) == 0 && sz > 0) {
            WPM(cave + offTrampoline, enc, sz);
            printf("[*] trampoline: %zu bytes\n", sz);
        }
        if (enc) ks_free(enc);
        ks_close(ks);
    }
};
