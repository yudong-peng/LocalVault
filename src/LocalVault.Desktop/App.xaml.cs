using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Windows;

namespace LocalVault.Desktop;

public partial class App : Application
{
    private Mutex? mutex;
    private bool ownsMutex;
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var user = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        mutex = new Mutex(true, "Local\\LocalVault-" + user, out ownsMutex);
        if (!ownsMutex)
        { MessageBox.Show("保险库已经在运行，请切换到已打开的窗口。", "本地保险库"); Shutdown(); return; }
        DispatcherUnhandledException += (_, args) =>
        {
            (MainWindow as MainWindow)?.LockVault();
            MessageBox.Show("操作出现异常，保险库已锁定。请重新打开后检查数据。", "本地保险库");
            args.Handled = true; // Do not display exception text or log secret-bearing objects.
        };
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LocalVault");
        Directory.CreateDirectory(folder);
        MainWindow = new MainWindow(Path.Combine(folder, "vault.db"));
        MainWindow.Show();
    }
    protected override void OnExit(ExitEventArgs e)
    {
        if (ownsMutex) mutex?.ReleaseMutex();
        mutex?.Dispose();
        base.OnExit(e);
    }
}
