using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Threading;

namespace LocalVault.Desktop;

internal static class SystemIdle
{
    [StructLayout(LayoutKind.Sequential)] private struct LastInput { public uint Size; public uint Time; }
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetLastInputInfo(ref LastInput input);
    public static TimeSpan Duration()
    {
        var input = new LastInput { Size = (uint)Marshal.SizeOf<LastInput>() };
        if (!GetLastInputInfo(ref input)) return TimeSpan.MaxValue; // fail closed
        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - input.Time));
    }
}

internal sealed class PrivateClipboard : IDisposable
{
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(20) };
    private uint? ownedSequence;
    public PrivateClipboard() { timer.Tick += (_, _) => ClearOwned(); }
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EmptyClipboard();
    [DllImport("user32.dll")] private static extern IntPtr SetClipboardData(uint format, IntPtr data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterClipboardFormat(string name);
    [DllImport("user32.dll")] private static extern uint GetClipboardSequenceNumber();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GlobalAlloc(uint flags, nuint bytes);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalLock(IntPtr memory);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GlobalUnlock(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr memory);
    private static void Put(uint format, byte[] bytes)
    {
        var handle = GlobalAlloc(0x0002, (nuint)bytes.Length);
        if (handle == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var pointer = GlobalLock(handle);
            if (pointer == IntPtr.Zero) throw new Win32Exception();
            try { Marshal.Copy(bytes, 0, pointer, bytes.Length); } finally { GlobalUnlock(handle); }
            if (SetClipboardData(format, handle) == IntPtr.Zero) throw new Win32Exception();
            handle = IntPtr.Zero; // system owns the allocation now
        }
        finally { if (handle != IntPtr.Zero) GlobalFree(handle); }
    }
    public void Copy(string value, IntPtr owner)
    {
        if (!OpenClipboard(owner)) throw new IOException("剪贴板正被其他程序占用，请稍后重试。");
        var bytes = Encoding.Unicode.GetBytes(value + "\0");
        try
        {
            if (!EmptyClipboard()) throw new Win32Exception();
            Put(13, bytes); // CF_UNICODETEXT
            Put(RegisterClipboardFormat("CanIncludeInClipboardHistory"), new byte[4]);
            Put(RegisterClipboardFormat("CanUploadToCloudClipboard"), new byte[4]);
        }
        catch { EmptyClipboard(); throw; }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); CloseClipboard(); }
        ownedSequence = GetClipboardSequenceNumber(); timer.Stop(); timer.Start();
    }
    public void ClearOwned()
    {
        timer.Stop();
        if (ownedSequence is null) return;
        if (!OpenClipboard(IntPtr.Zero)) { timer.Interval = TimeSpan.FromSeconds(1); timer.Start(); return; }
        try { if (GetClipboardSequenceNumber() == ownedSequence.Value) EmptyClipboard(); }
        finally { CloseClipboard(); ownedSequence = null; timer.Interval = TimeSpan.FromSeconds(20); }
    }
    public void Dispose() { ClearOwned(); timer.Stop(); }
}
