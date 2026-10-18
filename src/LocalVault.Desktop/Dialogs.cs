using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using LocalVault.Core;

namespace LocalVault.Desktop;

internal sealed class PasswordDialog : Window
{
    private readonly PasswordBox password = new();
    public string Password { get; private set; } = "";
    public PasswordDialog(Window owner, string title, string explanation)
    {
        Owner = owner; Title = title; Width = 440; Height = 260; ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(Ui.Text(explanation)); panel.Children.Add(password);
        var ok = Ui.Button("确认", () => { Password = password.Password; DialogResult = true; }, true);
        ok.IsDefault = true;
        panel.Children.Add(ok); Content = panel;
        Loaded += (_, _) => password.Focus();
        Closed += (_, _) => password.Clear();
    }
    public void Clear() => Password = "";
}

internal sealed class ChangePasswordDialog : Window
{
    public PasswordBox Current { get; } = new();
    public PasswordBox Next { get; } = new();
    public PasswordBox Confirm { get; } = new();
    public ChangePasswordDialog(Window owner)
    {
        Owner = owner; Title = "修改主密码"; Width = 480; Height = 470;
        ResizeMode = ResizeMode.NoResize; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(Ui.Text("旧备份仍使用备份生成时的主密码。修改后请生成新备份。"));
        panel.Children.Add(Ui.Text("当前主密码")); panel.Children.Add(Current);
        panel.Children.Add(Ui.Text("新主密码（至少 12 个字符）")); panel.Children.Add(Next);
        panel.Children.Add(Ui.Text("再次输入新主密码")); panel.Children.Add(Confirm);
        panel.Children.Add(Ui.Button("修改主密码", () =>
        {
            if (Next.Password.Length < 12 || Next.Password.Length > 1024 || Next.Password != Confirm.Password)
            { MessageBox.Show(this, "新主密码长度应为 12～1024 个字符，两次输入必须一致。"); return; }
            DialogResult = true;
        }, true));
        Content = panel;
    }
    public void Clear() { Current.Clear(); Next.Clear(); Confirm.Clear(); }
}

