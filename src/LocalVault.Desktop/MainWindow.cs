using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using LocalVault.Core;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Microsoft.Win32;

namespace LocalVault.Desktop;

public sealed partial class MainWindow : Window
{
    private readonly VaultStore store;
    private VaultSession? session;
    private readonly WebView2 web = new();
    private readonly PrivateClipboard clipboard = new();
    private readonly DispatcherTimer idle = new() { Interval = TimeSpan.FromSeconds(1) };
    private WindowsHelloKey? hello;
    private bool ready, busy, helloAvailable, closing;
    private long epoch;
    private DateTimeOffset nextAttempt;
    private int failures;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public MainWindow(string path)
    {
        store = new VaultStore(path); Title = "LocalVault · 本地保险库 0.5.0";
        Icon = new System.Windows.Media.Imaging.IconBitmapDecoder(new Uri("pack://application:,,,/Assets/app.ico"), System.Windows.Media.Imaging.BitmapCreateOptions.PreservePixelFormat, System.Windows.Media.Imaging.BitmapCacheOption.OnLoad).Frames.OrderByDescending(frame => frame.PixelWidth).First();
        Width = 1220; Height = 830; MinWidth = 960; MinHeight = 650;
        WindowStartupLocation = WindowStartupLocation.CenterScreen; Content = web;
        Loaded += async (_, _) => await InitializeAsync();
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        StateChanged += (_, _) => { if (WindowState == WindowState.Minimized) LockVault(); };
        PreviewKeyDown += (_, e) =>
        { if (e.Key == Key.L && Keyboard.Modifiers == ModifierKeys.Control) { LockVault(); e.Handled = true; } };
        idle.Tick += (_, _) =>
        { if (session is not null && SystemIdle.Duration() >= TimeSpan.FromMinutes(session.IdleMinutes)) LockVault(); };
        Closing += (_, _) =>
        {
            closing = true; epoch++; idle.Stop(); session?.Dispose(); session = null;
            clipboard.Dispose(); web.Dispose();
            SystemEvents.SessionSwitch -= OnSessionSwitch;
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        };
    }
    private async Task InitializeAsync()
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            hello = new WindowsHelloKey(Path.GetDirectoryName(store.FilePath)!, hwnd);
            helloAvailable = await WindowsHelloKey.IsAvailableAsync();
            web.CreationProperties = new CoreWebView2CreationProperties
            {
                UserDataFolder = Path.Combine(Path.GetDirectoryName(store.FilePath)!, "web-runtime"),
                IsInPrivateModeEnabled = true,
                AdditionalBrowserArguments = "--disable-background-networking --disable-component-update --disable-sync --no-first-run"
            };
            await web.EnsureCoreWebView2Async();
            if (closing) return;
            var core = web.CoreWebView2;
            var settings = core.Settings;
            settings.AreDevToolsEnabled = false; settings.AreHostObjectsAllowed = false;
            settings.AreDefaultScriptDialogsEnabled = false; settings.AreDefaultContextMenusEnabled = false;
            settings.AreBrowserAcceleratorKeysEnabled = false; settings.IsStatusBarEnabled = false;
            settings.IsPasswordAutosaveEnabled = false; settings.IsGeneralAutofillEnabled = false;
            settings.IsWebMessageEnabled = true;
            core.SetVirtualHostNameToFolderMapping("localvault.invalid", Path.Combine(AppContext.BaseDirectory, "Web"), CoreWebView2HostResourceAccessKind.DenyCors);
            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            core.WebResourceRequested += (_, args) =>
            {
                if (!LocalUiPolicy.IsLocalResource(args.Request.Uri))
                    args.Response = core.Environment.CreateWebResourceResponse(new MemoryStream([]), 403, "Blocked", "Content-Type: text/plain");
            };
            core.NavigationStarting += (_, args) => { if (!LocalUiPolicy.IsTrustedPage(args.Uri)) args.Cancel = true; };
            core.FrameNavigationStarting += (_, args) => args.Cancel = true;
            core.NewWindowRequested += (_, args) => args.Handled = true;
            core.DownloadStarting += (_, args) => args.Cancel = true;
            core.PermissionRequested += (_, args) => args.State = CoreWebView2PermissionState.Deny;
            core.ProcessFailed += (_, _) => { LockVault(); web.Visibility = Visibility.Hidden; MessageBox.Show(this, "网页渲染组件异常，保险库已锁定。请关闭并重新打开软件。"); };
            core.WebMessageReceived += HandleMessage;
            ready = true; core.Navigate(LocalUiPolicy.Page); idle.Start();
        }
        catch (WebView2RuntimeNotFoundException)
        {
            MessageBox.Show(this, "本机缺少 Microsoft Edge WebView2 Runtime。\n请关闭软件，运行程序包 Prerequisites 文件夹中的官方离线安装程序，再重新打开。无需联网下载。", "缺少本地渲染组件");
            Close();
        }
        catch
        { MessageBox.Show(this, "本地网页界面未能启动。请确认程序包已完整解压且 Web 文件夹存在。", "启动失败"); Close(); }
    }
    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    { if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect) Dispatcher.Invoke(LockVault); }
    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    { if (e.Mode == PowerModes.Suspend) Dispatcher.Invoke(LockVault); }
    public void LockVault()
    {
        epoch++;
        foreach (Window child in OwnedWindows.Cast<Window>().ToArray()) child.Close();
        session?.Dispose(); session = null; clipboard.ClearOwned();
        Send(new { type = "locked", epoch, data = State() });
    }
    private void Send(object value)
    {
        if (ready && !closing && web.CoreWebView2 is not null && LocalUiPolicy.IsTrustedPage(web.CoreWebView2.Source))
            web.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(value, Json));
    }
    private async void HandleMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        if (!LocalUiPolicy.IsTrustedPage(args.Source) || !LocalUiPolicy.IsTrustedPage(web.CoreWebView2.Source)) return;
        WebRequest? request;
        try
        {
            if (args.WebMessageAsJson.Length > 2 * 1024 * 1024) return;
            request = JsonSerializer.Deserialize<WebRequest>(args.WebMessageAsJson, Json);
            if (request is null || request.Id.Length is < 1 or > 80 || request.Action.Length > 40) return;
        }
        catch { return; }
        if (request.Action == "lock")
        { LockVault(); Send(new { id = request.Id, ok = true, data = State(), epoch }); return; }
        if (busy) { Send(new { id = request.Id, ok = false, error = "请等待当前操作完成。", epoch }); return; }
        busy = true;
        try
        {
            if (request.Action != "status" && request.Epoch != epoch) throw new InvalidOperationException("会话已改变，请重新解锁。");
            object? result = await DispatchAsync(request);
            Send(new { id = request.Id, ok = true, data = result, epoch });
        }
        catch (Exception error)
        {
            var message = SafeError(error);
            if (error is HelloOperationException && !closing) MessageBox.Show(this, message, "Windows Hello 诊断", MessageBoxButton.OK, MessageBoxImage.Information);
            Send(new { id = request.Id, ok = false, error = message, epoch });
        }
        finally { busy = false; }
    }
    private object State()
    {
        bool configured = false;
        try { configured = File.Exists(store.FilePath) && hello?.Enabled == true && hello.Read().HeaderBinding == store.HeaderBinding(); } catch { }
        var data = session?.Snapshot();
        DateTimeOffset? automatic = null;
        if (session is not null) try { automatic = session.LatestAutomaticBackupUtc(); } catch { }
        return new
        {
            unlocked = session is not null, hasVault = File.Exists(store.FilePath), epoch,
            helloAvailable, helloEnabled = configured, version = "0.5.0",
            idleMinutes = data?.IdleMinutes ?? 5, trashRetentionDays = data?.TrashRetentionDays ?? 30,
            contentRevision = data?.ContentRevision ?? 0, lastManualBackupUtc = data?.LastManualBackupUtc,
            hasUnexportedChanges = data?.HasUnexportedChanges ?? false, automaticBackupUtc = automatic,
            quickFillPresets = data?.QuickFillPresets.Select(p => new { p.Id, p.Label, p.Kind }).ToArray(),
            entries = data?.Entries.Select(e => new
            {
                id = e.Id, name = e.Title, category = e.Category, tags = VaultQuery.ParseTags(e.Tags),
                summary = VaultQuery.Summary(e), loginSummary = string.Join(" / ", e.LoginMethods.SelectMany(m => new[] { m.DisplayName, m.Identity })), favorite = e.IsFavorite, updated = e.UpdatedAt, deletedAt = e.DeletedAt
            }).ToArray()
        };
    }
    private VaultSession RequireSession() => session ?? throw new InvalidOperationException("保险库已锁定，请重新解锁。");
    private T Payload<T>(WebRequest request) => request.Payload.Deserialize<T>(Json) ?? throw new InvalidDataException();
    private VaultEntry FindEntry(Guid id) => RequireSession().Snapshot().Entries.Single(e => e.Id == id);
    private object EntryInfo(Guid id, bool forEdit)
    {
        var entry = FindEntry(id);
        return new
        {
            id = entry.Id, name = entry.Title, category = entry.Category, tags = VaultQuery.ParseTags(entry.Tags),
            notes = entry.Notes, favorite = entry.IsFavorite, deletedAt = entry.DeletedAt,
            loginMethods = entry.LoginMethods,
            fields = entry.Fields.Select((f, index) => new { index, name = f.Name, secret = f.Secret,
                value = f.Secret && !forEdit ? "" : f.Value, hasValue = f.Value.Length > 0 }).ToArray()
        };
    }
    private bool ConfirmPassword(string explanation)
    {
        var active = RequireSession(); var start = epoch;
        if (DateTimeOffset.UtcNow < nextAttempt) throw new InvalidOperationException("请稍候再试。");
        var dialog = new PasswordDialog(this, "验证主密码", explanation);
        try
        {
            if (dialog.ShowDialog() != true) return false;
            EnsureCurrent(start, active);
            active.VerifyPassword(dialog.Password); failures = 0; nextAttempt = default; return true;
        }
        catch { FailedAttempt(); throw; }
        finally { dialog.Clear(); }
    }
    private void EnsureCurrent(long start, VaultSession? active = null)
    {
        if (closing || epoch != start || (active is not null && !ReferenceEquals(active, session)))
            throw new OperationCanceledException();
    }
    private void FailedAttempt()
    { failures++; nextAttempt = DateTimeOffset.UtcNow.AddSeconds(Math.Min(30, failures * 2)); }
    private static string SafeError(Exception error) => error switch
    {
        HelloOperationException helloError => helloError.UserMessage(),
        OperationCanceledException => "操作已取消，保险库仍保持锁定或原有状态。",
        VaultAuthenticationException => "主密码错误，或解锁凭据已失效。请尝试主密码或有效备份。",
        CryptographicException => "Windows Hello 未完成验证，或此设备不支持所需密钥保护。请使用主密码；必要时重新配置 Windows Hello。",
        UnauthorizedAccessException => "没有文件访问权限，请检查目录权限。",
        IOException => "文件操作未完成。请检查文件占用、同名备份、目录权限和磁盘空间。",
        InvalidDataException => "输入或文件格式不符合要求。",
        InvalidOperationException => "当前操作不可用，请确认保险库已解锁并等待操作完成。",
        ArgumentException => "输入不符合要求。主密码长度应为 12～1024 个字符。",
        _ => "操作未完成，请重新打开后再试。"
    };
    private sealed record WebRequest(string Id, string Action, long Epoch, JsonElement Payload);
    private sealed record Credentials(string Password, string? Confirm);
    private sealed record EntryRequest(Guid Id, bool ForEdit = false);
    private sealed record FieldRequest(Guid Id, int Index);
    private sealed record SettingsRequest(int IdleMinutes, int TrashRetentionDays);
    private sealed record PresetSaveRequest(QuickFillPreset Preset, long ExpectedRevision);
    private sealed record PresetDeleteRequest(Guid Id, long ExpectedRevision);
    private sealed record SaveEntryRequest(VaultEntry Entry, long ExpectedRevision);
}
