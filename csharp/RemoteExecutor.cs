// RemoteExecutor.cs — IAT hook + code-cave remote execution (x64)
// Requires keystone.dll in output directory.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class Payload
{
    public byte[] Code = new byte[4096];
    public int Len = 0;

    public bool Asm(string asmCode, ulong address = 0)
    {
        IntPtr ks = IntPtr.Zero;
        int err = KeystoneNative.ks_open(4, 8, ref ks);
        if (err != 0 || ks == IntPtr.Zero)
        {
            Console.WriteLine("[!] ks_open failed");
            return false;
        }
        int ret = KeystoneNative.ks_asm(ks, asmCode, address, out IntPtr encoding, out uint size, out uint _count);
        bool ok = false;
        if (ret == 0 && size > 0)
        {
            Marshal.Copy(encoding, Code, Len, (int)size);
            Len += (int)size;
            ok = true;
        }
        else
        {
            int errno = KeystoneNative.ks_errno(ks);
            IntPtr msgPtr = KeystoneNative.ks_strerror(errno);
            string msg = msgPtr != IntPtr.Zero ? Marshal.PtrToStringAnsi(msgPtr) ?? "unknown" : "unknown";
            Console.WriteLine($"[!] ks_asm: {msg}");
        }
        if (encoding != IntPtr.Zero) KeystoneNative.ks_free(encoding);
        KeystoneNative.ks_close(ks);
        return ok;
    }
}

internal static class KeystoneNative
{
    [DllImport("keystone", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ks_open(int arch, int mode, ref IntPtr ks);

    [DllImport("keystone", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ks_close(IntPtr ks);

    [DllImport("keystone", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ks_asm(IntPtr ks,
        [MarshalAs(UnmanagedType.LPStr)] string str,
        ulong address, out IntPtr encoding, out uint size, out uint count);

    [DllImport("keystone", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ks_free(IntPtr p);

    [DllImport("keystone", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ks_errno(IntPtr ks);

    [DllImport("keystone", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ks_strerror(int code);
}

public class RemoteExecutor
{
    public IntPtr Proc = IntPtr.Zero;
    public ulong Base = 0;
    public ulong ModuleSize = 0;
    public uint Pid = 0;
    public uint MainThreadId = 0;

    public ulong Cave = 0;
    public ulong CaveSize = 0;

    public ulong OffDone       = 0x00;
    public ulong OffRequest    = 0x01;
    public ulong OffError      = 0x02;
    public ulong OffOrigFunc   = 0x08;
    public ulong OffIATAddr    = 0x10;
    public ulong OffUserData   = 0x20;
    public ulong OffCode       = 0x2800;
    public ulong OffTrampoline = 0x3800;

    public bool IATHooked = false;
    public ulong IATEntryAddr = 0;
    public ulong OrigFuncAddr = 0;

    public bool Attach(string exeName, int timeoutSec = 60)
    {
        for (int i = 0; i < timeoutSec && Pid == 0; i++)
        {
            Pid = FindPID(exeName);
            if (Pid == 0) Thread.Sleep(1000);
        }
        if (Pid == 0) { Console.WriteLine($"[!] '{exeName}' not found"); return false; }
        Console.WriteLine($"[*] PID: {Pid}");

        Proc = Native.OpenProcess(0x001FFFFF, false, Pid);
        if (Proc == IntPtr.Zero) { Console.WriteLine($"[!] OpenProcess failed: {Marshal.GetLastWin32Error()}"); return false; }

        if (!GetModInfo(Pid, exeName, out Base, out ModuleSize))
        { Console.WriteLine("[!] module info failed"); return false; }
        Console.WriteLine($"[*] Base: 0x{Base:X}  Size: 0x{ModuleSize:X}");

        MainThreadId = FindMainThread(Pid);
        if (MainThreadId == 0) { Console.WriteLine("[!] main thread not found"); return false; }
        Console.WriteLine($"[*] MainThread: {MainThreadId}");
        return true;
    }

    public bool RPM(ulong addr, byte[] buf, int len) =>
        Native.ReadProcessMemory(Proc, (IntPtr)(long)addr, buf, (IntPtr)len, out _);

    public bool WPM(ulong addr, byte[] buf, int len) =>
        Native.WriteProcessMemory(Proc, (IntPtr)(long)addr, buf, (IntPtr)len, out _);

    public T ReadVal<T>(ulong addr) where T : struct
    {
        int sz = Marshal.SizeOf<T>();
        byte[] buf = new byte[sz];
        RPM(addr, buf, sz);
        GCHandle h = GCHandle.Alloc(buf, GCHandleType.Pinned);
        T val = Marshal.PtrToStructure<T>(h.AddrOfPinnedObject());
        h.Free();
        return val;
    }

    public ulong ReadU64(ulong addr) { byte[] b = new byte[8]; RPM(addr, b, 8); return BitConverter.ToUInt64(b, 0); }
    public uint ReadU32(ulong addr)  { byte[] b = new byte[4]; RPM(addr, b, 4); return BitConverter.ToUInt32(b, 0); }
    public byte ReadU8(ulong addr)   { byte[] b = new byte[1]; RPM(addr, b, 1); return b[0]; }

    public void WriteU64(ulong addr, ulong val) => WPM(addr, BitConverter.GetBytes(val), 8);
    public void WriteU32(ulong addr, uint val)  => WPM(addr, BitConverter.GetBytes(val), 4);
    public void WriteU8(ulong addr, byte val)   => WPM(addr, new byte[] { val }, 1);
    public void WriteBytes(ulong addr, byte[] data) => WPM(addr, data, data.Length);

    public ulong Data(ulong offset = 0) => Cave + OffUserData + offset;
    public ulong CodeAddr() => Cave + OffCode;

    public bool AllocCave(ulong size = 0x4000)
    {
        CaveSize = size;
        IntPtr mem = Native.VirtualAllocEx(Proc, IntPtr.Zero, (IntPtr)(long)size, 0x3000, 0x40);
        if (mem == IntPtr.Zero) { Console.WriteLine("[!] VirtualAllocEx failed"); return false; }
        Cave = (ulong)(long)mem;
        byte[] zeros = new byte[size];
        WPM(Cave, zeros, (int)size);
        Console.WriteLine($"[*] Cave: 0x{Cave:X} ({size} bytes)");
        return true;
    }

    public void FreeCave()
    {
        if (Cave != 0) { Native.VirtualFreeEx(Proc, (IntPtr)(long)Cave, IntPtr.Zero, 0x8000); Cave = 0; }
    }

    public bool FindIATEntry(string dllName, string funcName, out ulong outIAT, out ulong outOrig)
    {
        outIAT = 0; outOrig = 0;
        ushort magic = ReadVal<ushort>(Base);
        if (magic != 0x5A4D) return false;
        int e_lfanew = ReadVal<int>(Base + 0x3C);
        ulong pe = Base + (ulong)e_lfanew;
        uint sig = ReadVal<uint>(pe);
        if (sig != 0x4550) return false;

        uint importRVA = ReadVal<uint>(pe + 0x90);
        if (importRVA == 0) return false;

        ulong imp = Base + importRVA;
        byte[] desc = new byte[20];
        for (int i = 0; i < 512; i++)
        {
            RPM(imp + (ulong)(i * 20), desc, 20);
            uint nameRVA = BitConverter.ToUInt32(desc, 12);
            uint thunkRVA = BitConverter.ToUInt32(desc, 16);
            if (nameRVA == 0 && thunkRVA == 0) break;

            string name = ReadString(Base + nameRVA, 63);
            if (!name.Equals(dllName, StringComparison.OrdinalIgnoreCase)) continue;

            uint origThunkRVA = BitConverter.ToUInt32(desc, 0);
            if (origThunkRVA == 0) origThunkRVA = thunkRVA;

            for (int j = 0; j < 4096; j++)
            {
                ulong ot = ReadU64(Base + origThunkRVA + (ulong)(j * 8));
                ulong it = ReadU64(Base + thunkRVA + (ulong)(j * 8));
                if (ot == 0) break;
                if ((ot & (1UL << 63)) != 0) continue;

                string fn = ReadString(Base + (uint)ot + 2, 127);
                if (fn == funcName)
                {
                    outIAT = Base + thunkRVA + (ulong)(j * 8);
                    outOrig = it;
                    return true;
                }
            }
        }
        return false;
    }

    public bool InstallHook()
    {
        var targets = new[] {
            ("USER32.dll", "TranslateMessage"),
            ("USER32.dll", "PeekMessageW"),
            ("USER32.dll", "DispatchMessageW"),
            ("USER32.dll", "GetMessageW"),
            ("KERNEL32.dll", "GetTickCount64"),
            ("KERNEL32.dll", "QueryPerformanceCounter"),
        };
        foreach (var (dll, func) in targets)
        {
            if (FindIATEntry(dll, func, out ulong iat, out ulong orig))
            {
                Console.WriteLine($"[*] Hook: {dll}!{func} @ 0x{iat:X}");
                return DoInstallHook(iat, orig);
            }
        }
        Console.WriteLine("[!] no suitable IAT entry");
        return false;
    }

    public void UninstallHook()
    {
        if (!IATHooked) return;
        Native.VirtualProtectEx(Proc, (IntPtr)(long)IATEntryAddr, (IntPtr)8, 4, out uint oldProt);
        WriteU64(IATEntryAddr, OrigFuncAddr);
        Native.VirtualProtectEx(Proc, (IntPtr)(long)IATEntryAddr, (IntPtr)8, oldProt, out _);
        IATHooked = false;
    }

    public void WriteCode(byte[] code, int len)
    {
        byte[] buf = new byte[len];
        Array.Copy(code, buf, len);
        WPM(Cave + OffCode, buf, len);
    }

    public void Trigger()
    {
        WriteU8(Cave + OffDone, 0);
        WriteU8(Cave + OffError, 0);
        WriteU8(Cave + OffRequest, 1);
    }

    public bool WaitDone(int timeoutMs = 5000)
    {
        for (int i = 0; i < timeoutMs; i++)
        {
            if (ReadU8(Cave + OffDone) != 0) return true;
            Thread.Sleep(1);
        }
        WriteU8(Cave + OffRequest, 0);
        Console.WriteLine($"[!] timeout ({timeoutMs}ms)");
        return false;
    }

    public bool HadError() => ReadU8(Cave + OffError) != 0;

    public bool Execute(Payload pl, int timeoutMs = 5000)
    {
        WriteCode(pl.Code, pl.Len);
        Trigger();
        return WaitDone(timeoutMs);
    }

    public void Cleanup()
    {
        UninstallHook();
        FreeCave();
        if (Proc != IntPtr.Zero) { Native.CloseHandle(Proc); Proc = IntPtr.Zero; }
    }

    public bool IsAlive() =>
        Native.GetExitCodeProcess(Proc, out uint code) && code == 259;

    public string ReadString(ulong addr, int maxLen)
    {
        byte[] buf = new byte[maxLen + 1];
        RPM(addr, buf, maxLen);
        int end = Array.IndexOf<byte>(buf, 0);
        if (end < 0) end = maxLen;
        return Encoding.ASCII.GetString(buf, 0, end);
    }

    private bool DoInstallHook(ulong iat, ulong orig)
    {
        IATEntryAddr = iat;
        OrigFuncAddr = orig;
        WriteU64(Cave + OffOrigFunc, orig);
        WriteU64(Cave + OffIATAddr, iat);
        BuildTrampoline();
        ulong tramp = Cave + OffTrampoline;
        Native.VirtualProtectEx(Proc, (IntPtr)(long)iat, (IntPtr)8, 4, out uint oldProt);
        WriteU64(iat, tramp);
        Native.VirtualProtectEx(Proc, (IntPtr)(long)iat, (IntPtr)8, oldProt, out _);
        IATHooked = true;
        Console.WriteLine("[+] hook installed");
        return true;
    }

    private static uint FindPID(string name)
    {
        foreach (var p in Process.GetProcesses())
        {
            try { if (p.ProcessName.Equals(System.IO.Path.GetFileNameWithoutExtension(name), StringComparison.OrdinalIgnoreCase)) return (uint)p.Id; }
            catch { }
        }
        return 0;
    }

    private static bool GetModInfo(uint pid, string modName, out ulong baseAddr, out ulong modSize)
    {
        baseAddr = 0; modSize = 0;
        IntPtr snap = Native.CreateToolhelp32Snapshot(0x08, pid);
        if (snap == (IntPtr)(-1)) return false;
        var me = new Native.MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<Native.MODULEENTRY32>() };
        if (Native.Module32First(snap, ref me))
        {
            do
            {
                if (me.szModule.Equals(modName, StringComparison.OrdinalIgnoreCase))
                {
                    baseAddr = (ulong)(long)me.modBaseAddr;
                    modSize = me.modBaseSize;
                    Native.CloseHandle(snap);
                    return true;
                }
            } while (Native.Module32Next(snap, ref me));
        }
        Native.CloseHandle(snap);
        return false;
    }

    private static uint FindMainThread(uint pid)
    {
        for (int i = 0; i < 50; i++)
        {
            IntPtr found = IntPtr.Zero;
            Native.EnumWindows((hwnd, _) =>
            {
                Native.GetWindowThreadProcessId(hwnd, out uint wndPid);
                if (wndPid == pid && Native.IsWindowVisible(hwnd))
                {
                    if (found == IntPtr.Zero) found = hwnd;
                    var sb = new StringBuilder(64);
                    Native.GetClassName(hwnd, sb, 64);
                    string cls = sb.ToString();
                    if (cls.Contains("UnrealWindow") || cls.Contains("Win32") || cls.Contains("Window"))
                    {
                        found = hwnd;
                        return false;
                    }
                }
                return true;
            }, IntPtr.Zero);
            if (found != IntPtr.Zero)
                return Native.GetWindowThreadProcessId(found, out _);
            Thread.Sleep(200);
        }
        return 0;
    }

    private void BuildTrampoline()
    {
        ulong aReq  = Cave + OffRequest;
        ulong aOrig = Cave + OffOrigFunc;
        ulong aCode = Cave + OffCode;

        string asm =
            $"push rax; mov rax, 0x{aReq:X}; cmp byte ptr [rax], 0; pop rax; je skip; " +
            "push rcx; push rdx; push r8; push r9; push r10; push r11; " +
            "sub rsp, 0x68; " +
            "movups [rsp], xmm0; movups [rsp+0x10], xmm1; " +
            "movups [rsp+0x20], xmm2; movups [rsp+0x30], xmm3; " +
            "movups [rsp+0x40], xmm4; movups [rsp+0x50], xmm5; " +
            $"mov rax, 0x{aCode:X}; call rax; " +
            "movups xmm0, [rsp]; movups xmm1, [rsp+0x10]; " +
            "movups xmm2, [rsp+0x20]; movups xmm3, [rsp+0x30]; " +
            "movups xmm4, [rsp+0x40]; movups xmm5, [rsp+0x50]; " +
            "add rsp, 0x68; " +
            "pop r11; pop r10; pop r9; pop r8; pop rdx; pop rcx; " +
            $"skip: mov rax, 0x{aOrig:X}; mov rax, [rax]; jmp rax";

        IntPtr ks = IntPtr.Zero;
        if (KeystoneNative.ks_open(4, 8, ref ks) != 0 || ks == IntPtr.Zero) return;
        int ret = KeystoneNative.ks_asm(ks, asm, 0, out IntPtr encoding, out uint size, out uint _);
        if (ret == 0 && size > 0)
        {
            byte[] code = new byte[size];
            Marshal.Copy(encoding, code, 0, (int)size);
            WPM(Cave + OffTrampoline, code, (int)size);
            Console.WriteLine($"[*] trampoline: {size} bytes");
        }
        if (encoding != IntPtr.Zero) KeystoneNative.ks_free(encoding);
        KeystoneNative.ks_close(ks);
    }
}

public static class Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, IntPtr size, uint type, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr proc, IntPtr addr, IntPtr size, uint type);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr proc, IntPtr addr, IntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr proc, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlssCntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    [DllImport("kernel32.dll")]
    public static extern bool Module32First(IntPtr snap, ref MODULEENTRY32 me);
    [DllImport("kernel32.dll")]
    public static extern bool Module32Next(IntPtr snap, ref MODULEENTRY32 me);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hwnd, StringBuilder name, int maxCount);

    public delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
}
