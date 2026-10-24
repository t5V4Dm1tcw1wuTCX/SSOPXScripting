// SSOExternal.cs — PXScript executor via code caves (PoC)
// Addresses provided as RVAs on the command line.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

class SSOExternal
{
    const uint INVALID_INDEX = 0x0BADF00D;

    struct PXMethod { public string Name; public uint Id; public int ArgType; }

    static readonly PXMethod[] Methods = {
        new(){ Name="Start", Id=1091, ArgType=0 }, new(){ Name="Stop", Id=1090, ArgType=0 },
        new(){ Name="ForceStart", Id=1089, ArgType=0 }, new(){ Name="Kill", Id=1095, ArgType=0 },
        new(){ Name="Delete", Id=1237, ArgType=0 },
        new(){ Name="ActionStart", Id=1083, ArgType=-1 }, new(){ Name="ActionStop", Id=1084, ArgType=-1 },
        new(){ Name="AddPosition", Id=1031, ArgType=7 },
        new(){ Name="Move", Id=1240, ArgType=32 }, new(){ Name="SetOrientationByObject", Id=1036, ArgType=32 },
        new(){ Name="GetActorPositionWSX", Id=1338, ArgType=3 },
        new(){ Name="GetActorPositionWSY", Id=1339, ArgType=3 },
        new(){ Name="GetActorPositionWSZ", Id=1340, ArgType=3 },
        new(){ Name="Position", Id=1019, ArgType=-1 },
        new(){ Name="AddViewText", Id=40117, ArgType=4 },
        new(){ Name="SetViewText", Id=40102, ArgType=4 }, new(){ Name="ViewText", Id=40102, ArgType=4 },
        new(){ Name="ViewTranslateText", Id=40122, ArgType=14 },
        new(){ Name="SetViewTextByTimeMinSec", Id=40113, ArgType=3 },
        new(){ Name="SetViewTextByTimeMinSecHun", Id=40115, ArgType=3 },
        new(){ Name="AddViewTextFloat", Id=40118, ArgType=3 },
        new(){ Name="AddViewTextInt", Id=40119, ArgType=1 },
        new(){ Name="AddViewTextUInt", Id=40120, ArgType=2 },
        new(){ Name="SetViewTextFromDataSource", Id=40121, ArgType=4 },
        new(){ Name="SetSkyModifierSkyColor", Id=83050, ArgType=10 },
        new(){ Name="SetSkyModifierHorizonColor", Id=83052, ArgType=10 },
        new(){ Name="SetSkyModifierColorMix", Id=83074, ArgType=3 },
        new(){ Name="StartSkyModifier", Id=83112, ArgType=-1 },
        new(){ Name="SetWorldDrawGlobalSpace", Id=26004, ArgType=1 },
        new(){ Name="QuestComplete", Id=123031, ArgType=0 },
        new(){ Name="QuestPlayerLevelChangeNotify", Id=123243, ArgType=0 },
        new(){ Name="QuestManagerCompleteSelected", Id=154004, ArgType=0 },
        new(){ Name="QuestManagerDiscardSelected", Id=154007, ArgType=0 },
        new(){ Name="QuestManagerSetQuestAvailable", Id=154011, ArgType=-1 },
        new(){ Name="QuestManagerSetQuestActive", Id=154012, ArgType=-1 },
        new(){ Name="QuestManagerSetQuestConditionsCompleted", Id=154013, ArgType=-1 },
        new(){ Name="QuestManagerSetQuestComplete", Id=154014, ArgType=-1 },
        new(){ Name="QuestManagerSetQuestFail", Id=154015, ArgType=-1 },
        new(){ Name="QuestManagerMoveToQuestGiver", Id=154017, ArgType=-1 },
        new(){ Name="QuestManagerMoveToQuestReceiver", Id=154018, ArgType=-1 },
        new(){ Name="DiscardQuest", Id=0x25997, ArgType=0 },
        new(){ Name="HorseCare", Id=0x1DCE3, ArgType=0 },
        new(){ Name="NetworkChristmasHack", Id=122085, ArgType=0 },
        new(){ Name="NetworkDebugAddXP", Id=122086, ArgType=-1 },
        new(){ Name="NetworkDebugAddHorseXP", Id=122087, ArgType=-1 },
        new(){ Name="NetworkDebugResetHorseLevel", Id=122088, ArgType=0 },
        new(){ Name="NetworkDebugAddMoney", Id=122089, ArgType=-1 },
        new(){ Name="NetworkDebugAddStarMoney", Id=122090, ArgType=-1 },
        new(){ Name="NetworkDebugResetStarMoney", Id=122091, ArgType=-1 },
        new(){ Name="NetworkHorseFreeWellbeing", Id=122083, ArgType=0 },
        new(){ Name="HorseRequestLevelUp", Id=120147, ArgType=0 },
        new(){ Name="HorseStartCallHorseTeleportSetup", Id=120137, ArgType=0 },
        new(){ Name="HorseMaxFallTime", Id=120266, ArgType=3 },
        new(){ Name="PlayerTPNetMaxFallTime", Id=226166, ArgType=3 },
        new(){ Name="HorseRestoreAppearance", Id=120170, ArgType=0 },
        new(){ Name="HorseAppearanceNormal", Id=120171, ArgType=0 },
        new(){ Name="HorseAppearanceCustomBody", Id=120173, ArgType=31 },
        new(){ Name="HorseAppearanceCustomHair", Id=120174, ArgType=31 },
        new(){ Name="CloneHorseAppearance", Id=120180, ArgType=-1 },
        new(){ Name="CloneHorse", Id=167002, ArgType=-1 },
        new(){ Name="HorseForSaleStartBuyWindow", Id=167007, ArgType=0 },
        new(){ Name="FileObjectLoad", Id=36000, ArgType=0 },
        new(){ Name="FactionAddReputation", Id=156008, ArgType=-1 },
        new(){ Name="FactionSetReputation", Id=156022, ArgType=-1 },
        new(){ Name="ShopOpen", Id=161016, ArgType=0 },
        new(){ Name="PlayerTPNetPlayAnimation", Id=226080, ArgType=4 },
        new(){ Name="PlayerTPNetPlayAnimationLooping", Id=226083, ArgType=4 },
        new(){ Name="PlayerTPNetPlayAnimationEnd", Id=226085, ArgType=0 },
        new(){ Name="RunScript", Id=1209, ArgType=4 },
        new(){ Name="GetPropertyValueAsString", Id=1223, ArgType=4 },
    };

    static RemoteExecutor rex = new();

    static ulong gFindActorAddr = 0;
    static ulong gExtractAddr   = 0;
    static ulong gRegistryAddr  = 0;
    static ulong gCtxOffset     = 0x190;

    const ulong SSO_OUTPUT     = 0x000;
    const ulong SSO_CONTEXT    = 0x010;
    const ulong SSO_LOCAL      = 0x020;
    const ulong SSO_SLOT       = 0x030;
    const ulong SSO_CONSUMED   = 0x040;
    const ulong SSO_FLAGS      = 0x044;
    const ulong SSO_SCENEROOT  = 0x048;
    const ulong SSO_PATH       = 0x050;
    const ulong SSO_ACTOR      = 0x250;
    const ulong SSO_VTB8       = 0x258;
    const ulong SSO_RESULT     = 0x260;
    const ulong SSO_ARGS       = 0x268;
    const ulong SSO_EXTRA      = 0x1268;
    const ulong SSO_VT8_CTX    = 0x2268;
    const ulong SSO_VT8_CMDID  = 0x2270;
    const ulong SSO_OUTPUT2    = 0x2280;
    const ulong SSO_PATH2      = 0x2290;

    // asm payload helpers

    static void AsmResolveActor(StringBuilder sb,
        ulong addrOutput, ulong addrPath, ulong addrActorOut, ulong addrVTB8Out)
    {
        sb.Append($"sub rsp, 0x68; ");
        sb.Append($"mov rax, 0x{gRegistryAddr:X}; mov rcx, [rax]; ");
        sb.Append($"mov rdx, 0x{addrOutput:X}; ");
        sb.Append($"mov r8, 0x{rex.Data(SSO_CONTEXT):X}; ");
        sb.Append($"mov r9, 0x{addrPath:X}; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_LOCAL):X}; mov [rsp+0x20], rax; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_SLOT):X}; mov [rsp+0x28], rax; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_CONSUMED):X}; mov [rsp+0x30], rax; ");
        sb.Append("mov qword ptr [rsp+0x38], 0; ");
        sb.Append("mov qword ptr [rsp+0x40], 0; ");
        sb.Append($"mov rax, 0x{gFindActorAddr:X}; call rax; ");
        sb.Append("add rsp, 0x68; ");
        sb.Append($"mov rax, 0x{addrOutput + 12:X}; mov eax, [rax]; ");
        sb.Append("cmp eax, 0x0BADF00D; je error; ");
        sb.Append("sub rsp, 0x28; ");
        sb.Append($"mov rcx, 0x{addrOutput:X}; ");
        sb.Append($"mov rax, 0x{gExtractAddr:X}; call rax; ");
        sb.Append($"mov rcx, 0x{addrActorOut:X}; mov [rcx], rax; ");
        sb.Append("add rsp, 0x28; ");
        sb.Append($"mov rax, 0x{addrActorOut:X}; mov rax, [rax]; mov rax, [rax]; mov rax, [rax+0x40]; ");
        sb.Append($"mov rcx, 0x{addrVTB8Out:X}; mov [rcx], rax; ");
    }

    static void AsmVtable8Call(StringBuilder sb,
        ulong addrActor, ulong addrCtx, ulong addrCmdId,
        ulong addrArgs, ulong addrExtra, ulong addrVTB8, ulong addrResult)
    {
        sb.Append("sub rsp, 0x38; ");
        sb.Append($"mov rax, 0x{addrActor:X}; mov rcx, [rax]; ");
        sb.Append($"mov rax, 0x{addrCtx:X}; mov rdx, [rax]; ");
        sb.Append($"mov rax, 0x{addrCmdId:X}; mov r8d, [rax]; ");
        sb.Append($"mov r9, 0x{addrArgs:X}; ");
        sb.Append($"mov rax, 0x{addrExtra:X}; mov [rsp+0x20], rax; ");
        sb.Append($"mov rax, 0x{addrVTB8:X}; mov rax, [rax]; call rax; ");
        sb.Append($"mov rcx, 0x{addrResult:X}; mov [rcx], rax; ");
        sb.Append("add rsp, 0x38; ");
    }

    static void AsmDoneError(StringBuilder sb)
    {
        sb.Append($"mov rax, 0x{rex.Cave + rex.OffError:X}; mov byte ptr [rax], 0; ");
        sb.Append($"mov rax, 0x{rex.Cave + rex.OffRequest:X}; mov byte ptr [rax], 0; ");
        sb.Append($"mov rax, 0x{rex.Cave + rex.OffDone:X}; mov byte ptr [rax], 1; ret; ");
        sb.Append("error: ");
        sb.Append($"mov rax, 0x{rex.Cave + rex.OffError:X}; mov byte ptr [rax], 1; ");
        sb.Append($"mov rax, 0x{rex.Cave + rex.OffRequest:X}; mov byte ptr [rax], 0; ");
        sb.Append($"mov rax, 0x{rex.Cave + rex.OffDone:X}; mov byte ptr [rax], 1; ret");
    }

    // payload builders

    static void BuildResolveAndCallPayload()
    {
        var sb = new StringBuilder(4096);
        AsmResolveActor(sb, rex.Data(SSO_OUTPUT), rex.Data(SSO_PATH), rex.Data(SSO_ACTOR), rex.Data(SSO_VTB8));
        AsmVtable8Call(sb, rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_VT8_CMDID),
            rex.Data(SSO_ARGS), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
        AsmDoneError(sb);
        var pl = new Payload();
        pl.Asm(sb.ToString());
        rex.WriteCode(pl.Code, pl.Len);
    }

    static void BuildCompoundPayload()
    {
        var sb = new StringBuilder(8192);
        AsmResolveActor(sb, rex.Data(SSO_OUTPUT), rex.Data(SSO_PATH), rex.Data(SSO_ACTOR), rex.Data(SSO_VTB8));
        AsmVtable8Call(sb, rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_OUTPUT2),
            rex.Data(SSO_PATH2), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
        AsmVtable8Call(sb, rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_VT8_CMDID),
            rex.Data(SSO_ARGS), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
        AsmDoneError(sb);
        var pl = new Payload();
        pl.Asm(sb.ToString());
        rex.WriteCode(pl.Code, pl.Len);
    }

    static void BuildArgType32Payload()
    {
        var sb = new StringBuilder(8192);
        AsmResolveActor(sb, rex.Data(SSO_OUTPUT), rex.Data(SSO_PATH), rex.Data(SSO_ACTOR), rex.Data(SSO_VTB8));

        // second resolve for arg actor
        sb.Append("sub rsp, 0x68; ");
        sb.Append($"mov rax, 0x{gRegistryAddr:X}; mov rcx, [rax]; ");
        sb.Append($"mov rdx, 0x{rex.Data(SSO_OUTPUT2):X}; ");
        sb.Append($"mov r8, 0x{rex.Data(SSO_CONTEXT):X}; ");
        sb.Append($"mov r9, 0x{rex.Data(SSO_PATH2):X}; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_LOCAL):X}; mov [rsp+0x20], rax; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_SLOT):X}; mov [rsp+0x28], rax; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_CONSUMED):X}; mov [rsp+0x30], rax; ");
        sb.Append("mov qword ptr [rsp+0x38], 0; ");
        sb.Append("mov qword ptr [rsp+0x40], 0; ");
        sb.Append($"mov rax, 0x{gFindActorAddr:X}; call rax; ");
        sb.Append("add rsp, 0x68; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_OUTPUT2) + 12:X}; mov eax, [rax]; ");
        sb.Append("cmp eax, 0x0BADF00D; je error; ");

        // copy SafeActorPtr (16 bytes) OUTPUT2 -> ARGS
        sb.Append($"mov rax, 0x{rex.Data(SSO_OUTPUT2):X}; ");
        sb.Append("mov rcx, [rax]; mov r8, [rax+0x08]; ");
        sb.Append($"mov rax, 0x{rex.Data(SSO_ARGS):X}; ");
        sb.Append("mov [rax], rcx; mov [rax+0x08], r8; ");

        AsmVtable8Call(sb, rex.Data(SSO_ACTOR), rex.Data(SSO_VT8_CTX), rex.Data(SSO_VT8_CMDID),
            rex.Data(SSO_ARGS), rex.Data(SSO_EXTRA), rex.Data(SSO_VTB8), rex.Data(SSO_RESULT));
        AsmDoneError(sb);
        var pl = new Payload();
        pl.Asm(sb.ToString());
        rex.WriteCode(pl.Code, pl.Len);
    }

    // cave data

    static void InitCaveData()
    {
        byte[] nullSafe = new byte[16];
        BitConverter.GetBytes(INVALID_INDEX).CopyTo(nullSafe, 12);
        rex.WriteBytes(rex.Data(SSO_OUTPUT), nullSafe);
        rex.WriteBytes(rex.Data(SSO_CONTEXT), nullSafe);
        rex.WriteBytes(rex.Data(SSO_LOCAL), nullSafe);
        rex.WriteBytes(rex.Data(SSO_SLOT), nullSafe);
    }

    static void PrepareResolveData(string path)
    {
        byte[] nullSafe = new byte[16];
        BitConverter.GetBytes(INVALID_INDEX).CopyTo(nullSafe, 12);
        rex.WriteBytes(rex.Data(SSO_OUTPUT), nullSafe);

        byte[] pathBuf = new byte[512];
        Encoding.ASCII.GetBytes(path, 0, Math.Min(path.Length, 511), pathBuf, 0);
        rex.WriteBytes(rex.Data(SSO_PATH), pathBuf);

        rex.WriteBytes(rex.Data(SSO_CONSUMED), new byte[4]);
        rex.WriteBytes(rex.Data(SSO_FLAGS), new byte[4]);
        rex.WriteBytes(rex.Data(SSO_SCENEROOT), new byte[8]);
    }

    // execution

    static bool TriggerAndWait()
    {
        ulong regPtr = rex.ReadU64(gRegistryAddr);
        ulong ctx = regPtr != 0 ? rex.ReadU64(regPtr + gCtxOffset) : 0;
        rex.WriteU64(rex.Data(SSO_VT8_CTX), ctx);

        rex.Trigger();
        if (!rex.WaitDone()) return false;
        if (rex.HadError()) { Console.WriteLine("[!] actor not found"); return false; }

        long result = rex.ReadVal<long>(rex.Data(SSO_RESULT));
        Console.WriteLine($"[+] vtable[8] ret = {result}");
        return true;
    }

    static bool RemoteCallVtable8(string actorPath, uint cmdId)
    {
        PrepareResolveData(actorPath);
        rex.WriteU32(rex.Data(SSO_VT8_CMDID), cmdId);
        BuildResolveAndCallPayload();
        return TriggerAndWait();
    }

    static bool RemoteCallCompound(string actorPath, uint cmdId1, byte[] args1, uint cmdId2)
    {
        PrepareResolveData(actorPath);
        rex.WriteU32(rex.Data(SSO_VT8_CMDID), cmdId2);
        rex.WriteU32(rex.Data(SSO_OUTPUT2), cmdId1);
        byte[] compArgs = new byte[512];
        if (args1 != null) Array.Copy(args1, compArgs, Math.Min(args1.Length, 512));
        rex.WriteBytes(rex.Data(SSO_PATH2), compArgs);
        BuildCompoundPayload();
        return TriggerAndWait();
    }

    static bool RemoteCallArgType32(string mainPath, string argActorPath, uint cmdId)
    {
        PrepareResolveData(mainPath);
        rex.WriteU32(rex.Data(SSO_VT8_CMDID), cmdId);

        byte[] nullSafe2 = new byte[16];
        BitConverter.GetBytes(INVALID_INDEX).CopyTo(nullSafe2, 12);
        rex.WriteBytes(rex.Data(SSO_OUTPUT2), nullSafe2);

        byte[] pathBuf2 = new byte[512];
        Encoding.ASCII.GetBytes(argActorPath, 0, Math.Min(argActorPath.Length, 511), pathBuf2, 0);
        rex.WriteBytes(rex.Data(SSO_PATH2), pathBuf2);

        BuildArgType32Payload();
        return TriggerAndWait();
    }

    // script parser

    struct ScriptArg { public bool IsStr; public string Str; public ulong Num; public bool IsFloat; }

    static PXMethod? LookupMethod(string name)
    {
        foreach (var m in Methods)
            if (m.Name == name) return m;
        return null;
    }

    static bool RunStatement(string defaultActor, string stmt)
    {
        int parenIdx = stmt.IndexOf('(');
        if (parenIdx < 0) { Console.WriteLine("[!] missing '('"); return false; }
        int closeIdx = stmt.LastIndexOf(')');
        if (closeIdx < 0) { Console.WriteLine("[!] missing ')'"); return false; }

        int dotIdx = stmt.LastIndexOf('.', parenIdx);
        if (dotIdx < 0) { Console.WriteLine("[!] expected path.Method(...)"); return false; }

        string path = stmt.Substring(0, dotIdx);
        string method = stmt.Substring(dotIdx + 1, parenIdx - dotIdx - 1);
        string argStr = stmt.Substring(parenIdx + 1, closeIdx - parenIdx - 1).Trim();
        string usePath = (path == "this") ? defaultActor : path;

        uint cmdId = 0;
        int argType = -1;

        if (method.StartsWith("#"))
        {
            cmdId = Convert.ToUInt32(method.Substring(1), method.Substring(1).StartsWith("0x") ? 16 : 10);
            if (cmdId == 0) { Console.WriteLine("[!] invalid #ID"); return false; }
        }
        else
        {
            var m = LookupMethod(method);
            if (m == null)
            {
                Console.WriteLine($"[*] unknown '{method}' -> RunScript");
                cmdId = 1209; argType = 4;
                string runBuf = $"this.{method}{stmt.Substring(parenIdx)}";

                byte[] argsBuf = new byte[4096];
                ulong remHeap = 0;
                int len = runBuf.Length;
                if (len <= 15)
                {
                    Encoding.ASCII.GetBytes(runBuf, 0, len, argsBuf, 0);
                    BitConverter.GetBytes((ulong)len).CopyTo(argsBuf, 16);
                    BitConverter.GetBytes((ulong)15).CopyTo(argsBuf, 24);
                }
                else
                {
                    IntPtr mem = Native.VirtualAllocEx(rex.Proc, IntPtr.Zero, (IntPtr)(len + 1), 0x3000, 0x04);
                    if (mem == IntPtr.Zero) { Console.WriteLine("[!] heap alloc failed"); return false; }
                    remHeap = (ulong)(long)mem;
                    byte[] strBuf = new byte[len + 1];
                    Encoding.ASCII.GetBytes(runBuf, 0, len, strBuf, 0);
                    rex.WriteBytes(remHeap, strBuf);
                    BitConverter.GetBytes(remHeap).CopyTo(argsBuf, 0);
                    BitConverter.GetBytes((ulong)len).CopyTo(argsBuf, 16);
                    BitConverter.GetBytes((ulong)len).CopyTo(argsBuf, 24);
                }
                rex.WriteBytes(rex.Data(SSO_ARGS), argsBuf);
                rex.WriteBytes(rex.Data(SSO_EXTRA), new byte[4096]);

                bool ok = RemoteCallVtable8(usePath, cmdId);
                if (remHeap != 0)
                {
                    ulong rs = rex.ReadU64(rex.Data(SSO_ARGS));
                    if (rs != 0) Native.VirtualFreeEx(rex.Proc, (IntPtr)(long)rs, IntPtr.Zero, 0x8000);
                }
                return ok;
            }
            cmdId = m.Value.Id;
            argType = m.Value.ArgType;
        }

        // parse args
        var args = new List<ScriptArg>();
        if (!string.IsNullOrEmpty(argStr))
        {
            int i = 0;
            while (i < argStr.Length && args.Count < 4)
            {
                while (i < argStr.Length && char.IsWhiteSpace(argStr[i])) i++;
                if (i >= argStr.Length) break;

                if (argStr[i] == '"')
                {
                    i++;
                    var sb = new StringBuilder();
                    while (i < argStr.Length && argStr[i] != '"')
                    {
                        if (argStr[i] == '\\' && i + 1 < argStr.Length)
                        {
                            i++;
                            sb.Append(argStr[i] == 'n' ? '\n' : argStr[i] == 't' ? '\t' : argStr[i]);
                            i++;
                        }
                        else sb.Append(argStr[i++]);
                    }
                    if (i < argStr.Length) i++;
                    args.Add(new ScriptArg { IsStr = true, Str = sb.ToString() });
                }
                else
                {
                    int start = i;
                    while (i < argStr.Length && argStr[i] != ',') i++;
                    string token = argStr.Substring(start, i - start).Trim();
                    bool isFloat = token.Contains('.') || token.Contains('e') || token.Contains('E');
                    bool isNum = token.Length > 0 && (char.IsDigit(token[0]) || token[0] == '-' || token[0] == '+' || token[0] == '.');
                    if (!isNum)
                        args.Add(new ScriptArg { IsStr = true, Str = token });
                    else if (isFloat)
                    {
                        float f = float.Parse(token, System.Globalization.CultureInfo.InvariantCulture);
                        uint bits = BitConverter.ToUInt32(BitConverter.GetBytes(f), 0);
                        args.Add(new ScriptArg { Num = bits, IsFloat = true });
                    }
                    else
                    {
                        ulong val = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                            ? Convert.ToUInt64(token.Substring(2), 16)
                            : ulong.Parse(token);
                        args.Add(new ScriptArg { Num = val });
                    }
                }
                while (i < argStr.Length && char.IsWhiteSpace(argStr[i])) i++;
                if (i < argStr.Length && argStr[i] == ',') i++;
            }
        }

        // marshal args
        byte[] argsBufM = new byte[4096];
        byte[] extraBufM = new byte[4096];
        ulong remHeapM = 0;

        float NumToFloat(ScriptArg a)
        {
            if (a.IsFloat) { uint b = (uint)a.Num; return BitConverter.ToSingle(BitConverter.GetBytes(b), 0); }
            return (float)(long)a.Num;
        }

        bool PutString(string s)
        {
            int len = s.Length;
            if (len <= 15)
            {
                Encoding.ASCII.GetBytes(s, 0, len, argsBufM, 0);
                BitConverter.GetBytes((ulong)len).CopyTo(argsBufM, 16);
                BitConverter.GetBytes((ulong)15).CopyTo(argsBufM, 24);
            }
            else
            {
                if (len > 250) len = 250;
                IntPtr mem = Native.VirtualAllocEx(rex.Proc, IntPtr.Zero, (IntPtr)(len + 1), 0x3000, 0x04);
                if (mem == IntPtr.Zero) return false;
                remHeapM = (ulong)(long)mem;
                byte[] strBuf = new byte[len + 1];
                Encoding.ASCII.GetBytes(s, 0, len, strBuf, 0);
                rex.WriteBytes(remHeapM, strBuf);
                BitConverter.GetBytes(remHeapM).CopyTo(argsBufM, 0);
                BitConverter.GetBytes((ulong)len).CopyTo(argsBufM, 16);
                BitConverter.GetBytes((ulong)len).CopyTo(argsBufM, 24);
            }
            return true;
        }

        bool okM = true;
        if (argType == 4)
        {
            string s = "";
            if (args.Count >= 1) s = args[0].IsStr ? args[0].Str : args[0].Num.ToString();
            okM = PutString(s);
        }
        else if (argType == 7)
        {
            for (int i = 0; i < 3; i++)
            {
                float f = (i < args.Count && !args[i].IsStr) ? NumToFloat(args[i]) : 0f;
                BitConverter.GetBytes(f).CopyTo(argsBufM, i * 4);
            }
        }
        else if (argType == 1 || argType == 2 || argType == 3 || argType == 14)
        {
            if (args.Count >= 1 && !args[0].IsStr)
            {
                if (argType == 3 && !args[0].IsFloat)
                {
                    float f = NumToFloat(args[0]);
                    uint bits = BitConverter.ToUInt32(BitConverter.GetBytes(f), 0);
                    BitConverter.GetBytes((ulong)bits).CopyTo(argsBufM, 0);
                }
                else BitConverter.GetBytes(args[0].Num).CopyTo(argsBufM, 0);
            }
        }
        else if (argType == 10)
        {
            for (int i = 0; i < 4; i++)
            {
                float f = (i < args.Count && !args[i].IsStr) ? NumToFloat(args[i]) : 0f;
                BitConverter.GetBytes(f).CopyTo(argsBufM, i * 4);
            }
        }
        else if (argType == 31)
        {
            for (int i = 0; i < args.Count; i++)
            {
                uint v = args[i].IsFloat ? (uint)NumToFloat(args[i]) : (uint)args[i].Num;
                BitConverter.GetBytes(v).CopyTo(argsBufM, i * 4);
            }
        }
        else if (argType == 32)
        {
            string argActorPath = (args.Count >= 1 && args[0].IsStr) ? args[0].Str : defaultActor;
            rex.WriteBytes(rex.Data(SSO_ARGS), argsBufM);
            rex.WriteBytes(rex.Data(SSO_EXTRA), extraBufM);
            return RemoteCallArgType32(usePath, argActorPath, cmdId);
        }
        else if (argType == 0) { /* no args */ }
        else
        {
            if (args.Count == 1 && !args[0].IsStr)
                BitConverter.GetBytes(args[0].Num).CopyTo(argsBufM, 0);
            else if (args.Count > 1)
            {
                bool hasFloat = false;
                foreach (var a in args) if (a.IsFloat) hasFloat = true;
                if (hasFloat)
                    for (int i = 0; i < args.Count; i++)
                        BitConverter.GetBytes(NumToFloat(args[i])).CopyTo(argsBufM, i * 4);
                else
                    for (int i = 0; i < args.Count; i++)
                        BitConverter.GetBytes((uint)args[i].Num).CopyTo(argsBufM, i * 4);
            }
        }

        if (!okM) return false;

        rex.WriteBytes(rex.Data(SSO_ARGS), argsBufM);
        rex.WriteBytes(rex.Data(SSO_EXTRA), extraBufM);

        // compound: ViewText -> ViewTranslateText(1) first
        if (cmdId == 40102)
        {
            byte[] flagBuf = BitConverter.GetBytes((uint)1);
            return RemoteCallCompound(usePath, 40122, flagBuf, cmdId);
        }

        bool ret = RemoteCallVtable8(usePath, cmdId);
        if (remHeapM != 0)
            Native.VirtualFreeEx(rex.Proc, (IntPtr)(long)remHeapM, IntPtr.Zero, 0x8000);
        return ret;
    }

    static void RunPXScript(string defaultActor, string script)
    {
        foreach (string raw in script.Split(';'))
        {
            string stmt = raw.Trim();
            if (string.IsNullOrEmpty(stmt)) continue;
            Console.WriteLine($"\n>>> {stmt}");
            RunStatement(defaultActor, stmt);
        }
    }

    static int Main(string[] argv)
    {
        if (argv.Length < 3)
        {
            Console.WriteLine("Usage: SSOExternal <ExtractActor_RVA> <FindActorByPath_RVA> <Registry_RVA> [CtxOffset]");
            Console.WriteLine("  All values in hex (0x prefix optional)");
            Console.WriteLine("  Example: SSOExternal 0x1A2B30 0x3C4D50 0x5E6F70");
            return 1;
        }

        ulong extractRVA = Convert.ToUInt64(argv[0].Replace("0x", "").Replace("0X", ""), 16);
        ulong findRVA    = Convert.ToUInt64(argv[1].Replace("0x", "").Replace("0X", ""), 16);
        ulong regRVA     = Convert.ToUInt64(argv[2].Replace("0x", "").Replace("0X", ""), 16);
        if (argv.Length >= 4) gCtxOffset = Convert.ToUInt64(argv[3].Replace("0x", "").Replace("0X", ""), 16);

        Console.WriteLine("=== SSOExternal PoC ===");
        if (!rex.Attach("SSOClient.exe", 300)) return 1;

        gExtractAddr   = rex.Base + extractRVA;
        gFindActorAddr = rex.Base + findRVA;
        gRegistryAddr  = rex.Base + regRVA;

        Console.WriteLine($"[*] ExtractActor:    0x{gExtractAddr:X}");
        Console.WriteLine($"[*] FindActorByPath: 0x{gFindActorAddr:X}");
        Console.WriteLine($"[*] Registry:        0x{gRegistryAddr:X}");
        Console.WriteLine($"[*] CtxOffset:       0x{gCtxOffset:X}");

        Console.WriteLine("[*] waiting for registry...");
        ulong regPtr = 0;
        for (int i = 0; i < 300 && regPtr == 0; i++)
        {
            regPtr = rex.ReadU64(gRegistryAddr);
            if (regPtr == 0) Thread.Sleep(100);
        }
        if (regPtr == 0) Console.WriteLine("[!] registry stayed NULL");
        else Console.WriteLine($"[+] registry: 0x{regPtr:X}");

        if (!rex.AllocCave()) { rex.Cleanup(); return 1; }
        InitCaveData();

        if (!rex.InstallHook()) { Console.WriteLine("[!] hook failed"); rex.Cleanup(); return 1; }

        Console.WriteLine("\nready. syntax: @actor path.Method(args);...");
        Console.WriteLine("  default actor: global/Horse");
        Console.WriteLine("  quit/exit to stop\n");

        while (true)
        {
            Console.Write("> ");
            string? line = Console.ReadLine();
            if (line == null) break;
            line = line.Trim();
            if (line.Length == 0) continue;
            if (line.Equals("quit", StringComparison.OrdinalIgnoreCase) ||
                line.Equals("exit", StringComparison.OrdinalIgnoreCase)) break;
            if (!rex.IsAlive()) { Console.WriteLine("[!] target exited"); break; }

            string actor = "global/Horse";
            string script = line;
            if (line.StartsWith("@"))
            {
                int sp = line.IndexOf(' ', 1);
                if (sp > 0)
                {
                    actor = line.Substring(1, sp - 1);
                    script = line.Substring(sp + 1);
                }
            }
            RunPXScript(actor, script);
        }

        rex.Cleanup();
        Console.WriteLine("bye.");
        return 0;
    }
}
