using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using LocalVault.Core;
using Microsoft.Win32;

namespace LocalVault.Desktop;

public sealed partial class MainWindow
{
    private async Task<object?> DispatchAsync(WebRequest request)
    {
        if (request.Action == "status") return State();
        if (request.Action is "unlock" or "create" or "helloUnlock")
        {
            if (session is not null) throw new InvalidOperationException();
            if (DateTimeOffset.UtcNow < nextAttempt) throw new InvalidOperationException();
            var start = epoch; VaultSession? opened = null;
            try
            {
                if (request.Action == "helloUnlock")
                {
                    var record = hello!.Read();
                    if (record.HeaderBinding != store.HeaderBinding()) throw new VaultAuthenticationException();
                    byte[]? payload = null;
                    try
                    {
                        payload = await Task.Run(() => hello.Decrypt(record.KeyName, record.Ciphertext, record.Version));
                        EnsureCurrent(start); opened = store.UnlockDevicePayload(payload);
                    }
                    finally { if (payload is not null) CryptographicOperations.ZeroMemory(payload); }
                }
                else
                {
                    var credentials = Payload<Credentials>(request);
                    if (request.Action == "create" && credentials.Password != credentials.Confirm) throw new ArgumentException();
                    opened = await Task.Run(() => request.Action == "create" ? store.Create(credentials.Password) : store.Unlock(credentials.Password));
                }
                EnsureCurrent(start); session = opened; opened = null; epoch++; failures = 0; nextAttempt = default;
                try { session.PurgeExpiredTrash(DateTimeOffset.UtcNow); } catch { /* Unlock must still permit export/recovery. */ }
                return State();
            }
            catch { FailedAttempt(); throw; }
            finally { opened?.Dispose(); }
        }
        if (request.Action == "restore") return RestoreBackup();
        var active = RequireSession(); var operationEpoch = epoch;
        switch (request.Action)
        {
            case "presetValue":
            case "presetGet":
                var selectedPreset = active.Snapshot().QuickFillPresets.Single(p => p.Id == Payload<EntryRequest>(request).Id);
                return request.Action == "presetValue" ? new { value = selectedPreset.Value } : (object)selectedPreset;
            case "presetSave":
                var presetSave = Payload<PresetSaveRequest>(request);
                active.UpsertQuickFillPreset(presetSave.Preset, presetSave.ExpectedRevision); return State();
            case "presetDelete":
                var presetDelete = Payload<PresetDeleteRequest>(request);
                if (MessageBox.Show(this, "确定删除这个常用项？已填入并保存的条目不会改变。", "删除常用项", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) throw new OperationCanceledException();
                EnsureCurrent(operationEpoch, active);
                active.DeleteQuickFillPreset(presetDelete.Id, presetDelete.ExpectedRevision); return State();
            case "entryGet":
                var get = Payload<EntryRequest>(request); return EntryInfo(get.Id, get.ForEdit);
            case "fieldReveal":
            case "fieldCopy":
                var fieldRequest = Payload<FieldRequest>(request);
                var entry = FindEntry(fieldRequest.Id);
                if (fieldRequest.Index < 0 || fieldRequest.Index >= entry.Fields.Count) throw new InvalidDataException();
                var value = entry.Fields[fieldRequest.Index].Value;
                if (request.Action == "fieldCopy") { clipboard.Copy(value, new System.Windows.Interop.WindowInteropHelper(this).Handle); return new { copied = true }; }
                return new { value };
            case "entrySave":
                var save = Payload<SaveEntryRequest>(request); var data = active.Snapshot();
                if (save.ExpectedRevision != data.ContentRevision) throw new InvalidOperationException();
                var replacement = save.Entry ?? throw new InvalidDataException();
                var existing = data.Entries.SingleOrDefault(e => e.Id == replacement.Id);
                if (existing?.DeletedAt is not null) throw new InvalidOperationException();
                replacement.DeletedAt = null; replacement.UpdatedAt = DateTimeOffset.UtcNow;
                if (existing is null) data.Entries.Add(replacement); else data.Entries[data.Entries.IndexOf(existing)] = replacement;
                active.Save(data); return State();
            case "favorite": active.ToggleFavorite(Payload<EntryRequest>(request).Id); return State();
            case "trashMove": active.MoveToTrash(Payload<EntryRequest>(request).Id); return State();
            case "trashRestore": active.RestoreEntry(Payload<EntryRequest>(request).Id); return State();
            case "trashDelete":
            case "trashEmpty":
                if (!ConfirmPassword("彻底删除无法撤销。请验证主密码。")) throw new OperationCanceledException();
                if (MessageBox.Show(this, "确定彻底删除？此操作无法撤销。", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) throw new OperationCanceledException();
                EnsureCurrent(operationEpoch, active);
                if (request.Action == "trashEmpty") active.EmptyTrash(); else active.PermanentlyDelete(Payload<EntryRequest>(request).Id);
                return State();
            case "settingsSet":
                var settings = Payload<SettingsRequest>(request); var updated = active.Snapshot();
                updated.IdleMinutes = settings.IdleMinutes; updated.TrashRetentionDays = settings.TrashRetentionDays;
                active.Save(updated); return State();
            case "backup":
                if (!ConfirmPassword("导出加密备份，请验证主密码。")) throw new OperationCanceledException();
                var destination = new SaveFileDialog { Filter = "LocalVault 加密备份|*.lvault", FileName = $"LocalVault-{DateTime.Now:yyyyMMdd-HHmmss}.lvault", AddExtension = true, DefaultExt = ".lvault" };
                if (destination.ShowDialog(this) != true) throw new OperationCanceledException();
                EnsureCurrent(operationEpoch, active);
                var result = active.ExportBackup(destination.FileName);
                if (!result.StatusRecorded) { LockVault(); MessageBox.Show(this, "备份已导出，但备份状态未能记录。保险库已锁定，请重新解锁。", "备份已导出"); }
                return State();
            case "helloEnable": await EnableHelloAsync(active, operationEpoch); return State();
            case "helloDisable":
                if (!ConfirmPassword("关闭本机 Windows Hello 解锁，请验证主密码。")) throw new OperationCanceledException();
                EnsureCurrent(operationEpoch, active); hello!.Disable(); return State();
            case "passwordChange":
                var dialog = new ChangePasswordDialog(this);
                try
                {
                    if (dialog.ShowDialog() != true) throw new OperationCanceledException();
                    EnsureCurrent(operationEpoch, active);
                    if (DateTimeOffset.UtcNow < nextAttempt) throw new InvalidOperationException();
                    try { active.VerifyPassword(dialog.Current.Password); }
                    catch { FailedAttempt(); throw; }
                    hello!.Disable(); active.ChangePassword(dialog.Current.Password, dialog.Next.Password); LockVault(); return State();
                }
                finally { dialog.Clear(); }
            case "openDataFolder":
                Process.Start(new ProcessStartInfo("explorer.exe", Path.GetDirectoryName(store.FilePath)!) { UseShellExecute = true }); return new { opened = true };
            default: throw new InvalidOperationException();
        }
    }
    private async Task EnableHelloAsync(VaultSession active, long start)
    {
        if (!helloAvailable || hello is null) throw new InvalidOperationException();
        if (DateTimeOffset.UtcNow < nextAttempt) throw new InvalidOperationException();
        var dialog = new PasswordDialog(this, "启用 Windows Hello", "输入当前主密码，再完成 Windows 验证。本机密钥不会随备份转移。请牢记主密码。");
        string password;
        try
        {
            if (dialog.ShowDialog() != true) throw new OperationCanceledException();
            EnsureCurrent(start, active); password = dialog.Password;
            try { active.VerifyPassword(password); } catch { FailedAttempt(); throw; }
        }
        finally { dialog.Clear(); }
        try { hello.Disable(); }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.RemovePrevious, error); }
        Activate();
        var name = hello.NewKeyName(); bool saved = false; byte[]? proof = null;
        try
        {
            await Task.Run(() => hello.Create(name)); EnsureCurrent(start, active);
            byte[] ciphertext;
            using (var protection = await Task.Run(() => hello.PrepareProtection(name)))
            {
                EnsureCurrent(start, active);
                ciphertext = active.ProtectForDevice(password, protection.Protect);
            }
            password = "";
            proof = await Task.Run(() => hello.Decrypt(name, ciphertext, 2)); EnsureCurrent(start, active);
            try { using (store.UnlockDevicePayload(proof)) { } }
            catch (Exception error) { throw HelloOperationException.Capture(HelloStage.ValidatePayload, error); }
            CryptographicOperations.ZeroMemory(proof); proof = null;
            await Task.Run(() => hello.VerifyNoCachedUnlock(name, ciphertext, 2)); EnsureCurrent(start, active);
            try { hello.Write(new HelloRecord(2, name, store.HeaderBinding(), ciphertext)); saved = true; }
            catch (Exception error) { throw HelloOperationException.Capture(HelloStage.SaveRecord, error); }
        }
        finally
        {
            password = "";
            if (proof is not null) CryptographicOperations.ZeroMemory(proof);
            if (!saved) try { hello.DeleteKey(name); } catch { /* An unusable orphan cannot unlock the vault without a sidecar. */ }
        }
    }
    private object RestoreBackup()
    {
        var start = epoch; var active = session;
        if (active is not null && !ConfirmPassword("恢复备份会替换当前保险库。请先验证当前主密码。")) throw new OperationCanceledException();
        var source = new OpenFileDialog { Filter = "LocalVault 保险库或备份|*.lvault;*.db|所有文件|*.*", CheckFileExists = true };
        if (source.ShowDialog(this) != true) throw new OperationCanceledException();
        EnsureCurrent(start, active);
        var password = new PasswordDialog(this, "验证备份", "请输入这个备份生成时的主密码。恢复前会先验证备份并保存当前库的恢复前副本。");
        try
        {
            if (password.ShowDialog() != true) throw new OperationCanceledException();
            EnsureCurrent(start, active);
            if (DateTimeOffset.UtcNow < nextAttempt) throw new InvalidOperationException();
            try { using var verification = new VaultStore(source.FileName).Unlock(password.Password); }
            catch { FailedAttempt(); throw; }
            if (MessageBox.Show(this, "备份验证通过。确定替换当前保险库？本机 Windows Hello 将被关闭。", "恢复加密备份", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) throw new OperationCanceledException();
            EnsureCurrent(start, active); hello!.Disable(); LockVault(); store.Restore(source.FileName, password.Password); return State();
        }
        finally { password.Clear(); }
    }
}
