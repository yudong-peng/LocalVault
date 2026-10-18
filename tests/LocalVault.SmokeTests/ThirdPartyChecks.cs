using System.Security.Cryptography;
using System.Text;
using LocalVault.Core;

internal static class ThirdPartyChecks
{
    public static void Run(string root, Action<bool,string> check, Action<Action,string> reject)
    {
        const string password="Public Test Probe Password 2026!";
        var path=Path.Combine(root,"third-party","vault.db");Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.Copy(Path.Combine(AppContext.BaseDirectory,"Fixtures","legacy-v040.fixture"),path);
        var original=SHA256.HashData(File.ReadAllBytes(path));var store=new VaultStore(path);
        using var session=store.Unlock(password);
        check(session.NeedsUpgrade&&session.Snapshot().FormatVersion==3&&session.Snapshot().QuickFillPresets.Count==1,"original v0.4 format-3 fixture loads presets without rewriting");
        check(original.SequenceEqual(SHA256.HashData(File.ReadAllBytes(path)))&&!Directory.Exists(store.BackupDirectory),"read-only format-3 open keeps file and backup directory unchanged");
        var passport=new VaultEntry{Title="QQ-PASSPORT-TEST",Fields=[new(){Name="账号",Value="QQ-IDENTITY-TEST"},new(){Name="密码",Value="PASSPORT-SECRET-TEST",Secret=true}]};
        var site=new VaultEntry{Title="SITE-THIRD-PARTY-TEST",Fields=[],LoginMethods=[new(){Kind="thirdParty",Provider="QQ",LinkedEntryId=passport.Id,Identity="PERSONAL-QQ-ALIAS-TEST"},new(){Kind="thirdParty",Provider="微信",Identity="WECHAT-ALIAS-TEST"},new(){Kind="sms",Identity="PHONE-TEST"},new(){Kind="thirdParty",Provider="其他",CustomProvider="SCHOOL-SSO-TEST"}]};
        var data=session.Snapshot();data.Entries.Add(passport);data.Entries.Add(site);session.Save(data);
        check(session.Snapshot().FormatVersion==4&&!session.NeedsUpgrade&&session.Snapshot().QuickFillPresets.Count==1,"third-party write upgrades to format 4 while retaining common presets");
        var before=Directory.EnumerateFiles(store.BackupDirectory,"before-upgrade-v0.5-*.lvault").Single();
        using(var rollback=new VaultStore(before).Unlock(password))check(rollback.NeedsUpgrade&&rollback.Snapshot().FormatVersion==3&&rollback.Snapshot().QuickFillPresets.Count==1,"format-3 rollback snapshot retains pre-upgrade common presets");
        using(var reopened=store.Unlock(password))check(reopened.Snapshot().Entries.Single(e=>e.Id==site.Id).LoginMethods.Count==4,"multiple third-party and code-login methods survive reopen");
        check(session.Snapshot().Entries.Single(e=>e.Id==site.Id).Fields.Count==0,"third-party-only platform requires no local account password fields");
        check(!new[]{"QQ-PASSPORT-TEST","PERSONAL-QQ-ALIAS-TEST","WECHAT-ALIAS-TEST","SCHOOL-SSO-TEST","PASSPORT-SECRET-TEST"}.Any(Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains),"providers, linked identities and passport secrets remain encrypted on disk");
        check(VaultQuery.Summary(site).Contains("QQ")&&VaultQuery.Summary(site).Contains("微信"),"list summary describes third-party login methods");
        check(VaultQuery.Filter(session.Snapshot(),search:"SCHOOL-SSO-TEST").Count==1&&VaultQuery.Filter(session.Snapshot(),search:"PERSONAL-QQ-ALIAS-TEST").Count==1,"provider name and identity hints can be searched in unlocked core");
        check(VaultQuery.Filter(session.Snapshot(),search:"PASSPORT-SECRET-TEST").Count==0,"login search does not include linked passport secret values");
        var changed=session.Snapshot();changed.Entries.Single(e=>e.Id==passport.Id).Title="Renamed QQ";session.Save(changed);
        check(session.Snapshot().Entries.Single(e=>e.Id==site.Id).LoginMethods[0].LinkedEntryId==passport.Id,"passport rename preserves stable link identity");
        session.MoveToTrash(passport.Id);
        check(session.Snapshot().Entries.Single(e=>e.Id==site.Id).LoginMethods[0].LinkedEntryId==passport.Id,"trashing passport preserves platform link without cascading deletion");
        session.RestoreEntry(passport.Id);session.MoveToTrash(passport.Id);session.PermanentlyDelete(passport.Id);
        check(session.Snapshot().Entries.Single(e=>e.Id==site.Id).LoginMethods[0].LinkedEntryId==passport.Id,"missing passport retains a stale link for explicit UI diagnosis");
        void Invalid(Action<VaultEntry> edit,string message){var candidate=session.Snapshot();edit(candidate.Entries.Single(e=>e.Id==site.Id));reject(()=>session.Save(candidate),message);}
        Invalid(e=>e.LoginMethods[0].LinkedEntryId=e.Id,"self-referencing passport link rejected");
        Invalid(e=>e.LoginMethods[0].Kind="remote-oauth","unknown login kind rejected");
        Invalid(e=>e.LoginMethods[0].Provider="unknown-provider","unknown provider requires explicit custom-provider mode");
        Invalid(e=>{e.LoginMethods[0].Provider="其他";e.LoginMethods[0].CustomProvider="";},"custom third-party provider must have a name");
        Invalid(e=>e.LoginMethods.Add(e.LoginMethods[0]),"duplicate login method IDs rejected");
        Invalid(e=>e.LoginMethods=Enumerable.Range(0,13).Select(_=>new LoginMethod()).ToList(),"login method count is bounded");
        Invalid(e=>e.LoginMethods[0].Identity=new string('x',201),"identity hint length is bounded");
        Invalid(e=>e.Category=Categories.All[1],"third-party methods cannot silently attach to non-account category");
        var wrongTarget=session.Snapshot();var api=new VaultEntry{Title="API target",Category=Categories.All[1]};wrongTarget.Entries.Add(api);wrongTarget.Entries.Single(e=>e.Id==site.Id).LoginMethods[0].LinkedEntryId=api.Id;
        reject(()=>session.Save(wrongTarget),"passport links to non-account entries are rejected");
        var backup=Path.Combine(root,"third-party-portable.lvault");session.ExportBackup(backup);
        var other=new VaultStore(Path.Combine(root,"third-party-other","vault.db"));other.Restore(backup,password);
        using(var recovered=other.Unlock(password))check(recovered.Snapshot().Entries.Single(e=>e.Id==site.Id).LoginMethods[1].Provider=="微信"&&recovered.Snapshot().QuickFillPresets.Count==1,"portable backup preserves login methods, stale links and common presets");
    }
}
