# LocalVault · 0.5.2 预览版

作者 / 团队：**Yudong Peng**。Windows 单人离线敏感信息保险库，本地 HTML/CSS/JavaScript 由 WebView2 渲染，C# 核心负责加密、文件、剪贴板和 Windows Hello。使用用户指定的猫耳保险库图标。文件元数据已设置，尚未做 Authenticode 数字签名。

## 本版功能

- 账号密码、大模型 API、哈希密钥、私密笔记四类条目；清晰标签、可选补充信息、自定义字段、实时预览。
- 账号类条目新增登录方式：账号密码、手机验证码、邮箱验证码，以及 QQ、微信、Apple、Google、Microsoft、GitHub、支付宝和自定义第三方通行证。一个平台可记录多种方式。
- 第三方登录可填写使用的账号/昵称，也可关联保险库中已有的账号类条目。详情可跳转查看关联通行证，通行证密码不复制到平台条目。改名保持关联；移入回收站或删除后明确提示关联不可用，平台记录保留。
- 常用账号/手机号/邮箱/密码，加密保存，表单按类型快速填入；密码菜单只显示名称。
- 收藏、标签、搜索、回收站、加密备份恢复、自动锁定、修改主密码，以及 Windows Hello 快捷解锁预览。

**第三方登录在本软件中是离线的登录关系记录。** 软件不联网发起 OAuth、获取验证码或替平台登录。没有远程服务器、本地 HTTP 服务、云同步或在线 API 测试。

## 运行与操作

完整解压 Windows x64 包，运行 `LocalVault.exe`。包含 .NET 10.0.13；若缺少 WebView2，关闭应用后运行 `Prerequisites` 中 Microsoft 官方完整离线安装器。不要只复制一个 EXE。

已有 v0.4.0 的用户也可使用小更新包，完全退出软件后，将其中 `LocalVault-win-x64` 内的内容复制到原程序目录，替换同名程序文件。小包依赖原目录完整的运行组件，不是独立成品。

首次设置 12～1024 字符主密码；已有库用原主密码。遗忘主密码无法重置，Hello 不是异机恢复凭据。

新增账号条目 → “这个平台支持哪些登录方式？” → 添加第三方通行证 → 选择 QQ/微信等 → 按需填写账号备注或关联已有条目。若仅使用通行证，可取消“账号密码”，账密输入框会收起。已填的备用账密不会因切换方式删除，勾选回来可编辑。至少保留一种方式。自定义通行证需要填写名称。

常用项：设置 → 常用账号与密码 → 管理常用项。填写名称、类型和实际值，最多 100 项。新增/编辑账号条目时在对应输入框下选择快速填入；草稿保存后是独立副本，之后修改常用项不会改变旧条目。

## Hello 兼容调整与复测

v0.5.2 针对“检查是否禁止静默解密 / 0x80090027”调整新注册路径：专用 Hello RSA 密钥以 SHA-256/PKCS#1 签名，校验后 HKDF-SHA256 派生 AES-256-GCM 凭据保护密钥。签名与临时密钥不写盘，不用 RSA PKCS#1 加密或 OAEP-SHA1，不跳过验证。系统私钥不可导出、强制每次验证和静默操作必须明确拒绝等检查仍保留；签名失败不会放行。旧版本 1 成功记录保留读取能力。

系统窗口出现和按下指纹不能代替后续保护检查。新版也需要用户设备复测，不能保证所有系统 Hello 设备都支持此路径。失败时显示固定步骤和状态码，不显示原始异常、路径、密钥名或密码。无需重置系统 Hello。更新与复测方法见《升级说明.md》。

## 数据、升级、迁移

固定数据目录 `%LOCALAPPDATA%\LocalVault`：`vault.db` 为整体加密数据库，`backups` 为加密副本，`hello.json` 为本机加密快捷解锁记录，`web-runtime` 为渲染配置。条目、登录方式/身份备注/关联 ID、常用项与设置均处于同一个加密载荷，没有额外明文关系表。

升级前先导出加密备份。v0.5 读取格式 1/2/3/4，首次改写旧格式前保存 `before-upgrade-v0.5-*.lvault`，再原子升级到格式 4；只读取不改写。备份失败则中止。旧 v0.1～v0.4 无法读格式 4，避免旧程序忽略登录关系后保存丢失；回退须恢复升级前快照，不含之后的新修改。格式升级使旧 Hello 绑定失效，主密码解锁后重新启用。

换电脑：导出 `.lvault` → 在新机恢复 → 输入备份生成时主密码 → 核对条目、登录方式和常用项 → 重新启用 Hello。系统私钥不随备份迁移。删除条目或常用项不清理历史备份，也不构成安全擦除。

## 验证和开发

195 项核心/签名保护检查、51 项 DOM/模拟通信检查通过，Windows x64 发布结果见 TEST-REPORT.md。原始 v0.4 核心实际拒绝格式 4 探针，确认不能静默丢失新元数据。**真实 Windows 图形界面、WebView2 原生通信、指纹/人脸/PIN 及新 NCrypt 调用仍待实机验收。** 请先使用虚构资料。

需要 .NET 10 SDK；首次还原开发依赖需要网络。运行软件不需要 Node、Python 或开发工具。

```powershell
dotnet run --project tests/LocalVault.SmokeTests -c Release
dotnet run --project src/LocalVault.Desktop
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

可选网页测试在 `tests/Web` 执行 `npm ci`、`npm test`，需要 Node.js。构建脚本支持 `-OfflineInstallerPath` 指定已有的官方 x64 离线安装器，无自动下载。

核心代码在 `src/LocalVault.Core`（含 `LoginMethod.cs`、`QuickFillPreset.cs`）；本地网页在 `src/LocalVault.Desktop/Web`；Hello 接口与安全诊断在 `WindowsHelloKey.cs`、`HelloOperationException.cs`。`tests` 含真实旧版本生成的公开虚构数据夹具，不是用户保险库。公开 Git 前排除数据库、备份、Hello 记录和渲染配置。

完整安全边界、许可证与验收范围见 `SECURITY.md`、`THIRD-PARTY-NOTICES.md`、`LICENSES` 和 `TEST-REPORT.md`。
