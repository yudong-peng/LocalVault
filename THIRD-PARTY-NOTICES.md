# 第三方依赖

开发和发布使用下列组件。各组件的原始许可证、版权及适用条款以其仓库和 NuGet 包为准；发布目录内随运行时附带的 `LICENSE.txt`、`ThirdPartyNotices.txt` 应一并保留。

| 组件 | 用途 | 来源 |
|---|---|---|
| .NET / Windows Desktop Runtime | C# 与 WPF 运行环境 | https://github.com/dotnet/runtime / https://github.com/dotnet/wpf |
| Microsoft.Data.Sqlite 10.0.13 | SQLite 托管接口 | https://github.com/dotnet/efcore |
| SQLitePCLRaw | SQLite 原生接口和分发依赖 | https://github.com/ericsink/SQLitePCL.raw |
| SQLite | 数据库引擎 | https://sqlite.org/copyright.html |
| Microsoft.Web.WebView2 1.0.4258.31 | 本地网页宿主 SDK 与加载器 | https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4258.31 |
| Microsoft Edge WebView2 Runtime（官方离线安装程序） | 系统网页渲染组件 | https://developer.microsoft.com/microsoft-edge/webview2/ |
| Konscious.Security.Cryptography.Argon2 1.3.1 | Argon2id 实现 | https://github.com/kmaragon/Konscious.Security.Cryptography |
| Konscious.Security.Cryptography.Blake2 | Argon2 使用的 BLAKE2 实现 | 同上 |

源代码包保留 `packages.lock.json`，其中列出完整解析依赖及内容哈希。主应用直接使用标准 AES-GCM 实现，没有自行设计密码算法。

WebView2 SDK 许可证见 `LICENSES/Microsoft.Web.WebView2-LICENSE.txt`。随包的官方 Runtime 安装程序保持原样，安装与运行适用 Microsoft 展示的条款；其系统更新机制独立于本应用。

`tests/Web` 可选开发测试依赖 linkedom 0.18.13（ISC）及锁文件所列依赖，仅供 DOM 模拟检查；不进入成品运行包。源代码未复制外部密码管理器实现。
