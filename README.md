# BLoader DevTools

BLoader DevTools 是在 Minecraft Bedrock 进程内运行的开源 BL Mod，使用 Rust + egui + DirectX 11。没有独立 UI EXE；UI 由 DLL 自行创建，使用独立的 Win32 游戏子窗口（必要时同进程顶层窗口）与消息/渲染线程。

- 版本：0.1.3
- 作者：Chlna6666
- 协议：GPL-3.0-only
- 源码：https://github.com/Chlna6666/BLoader-DevTools

## 安装（重要：不能只复制裸 DLL）

**BLoader 的裸 DLL 自动打包规则会把它归类为 `preload-native`，这种加载方式仅调用 `LoadLibrary`，不会执行 `bl_mod_main_v1` / `on_load`。因此旧版只有 DLL 的压缩包会造成“加载了却没有窗口和 DevTools 日志”的现象。**

请在 [Actions Windows 构建页面](https://github.com/Chlna6666/BLoader-DevTools/actions/workflows/windows-build.yml) 下载最新的 `bloader-devtools-windows-x64`，解压后把目录完整放进**正在运行的游戏版本目录**。目标结构：

```text
Minecraft 游戏版本目录/
└── mods/
    └── bloader.devtools/
        ├── manifest.json       # type 必须为 "BL"
        └── bloader_devtools.dll
```

也可以从仓库 `package/manifest.json` 复制清单，并将对应新版本 Release DLL 放在同一目录。**不要只把 DLL 放在 mods 根目录。**

如果之前已经安装了 `mods/bloader_devtools/` 自动生成的旧包（`manifest.json` 中 `type=preload-native`），请先移除旧包，避免重复加载或沿用错误的入口类型。

## 控制台诊断

加载成功时应先看到 BLoader 的 `Loading BL Mod: BLoader DevTools`，随后看到 DevTools 自己的：

```text
[BLoader DevTools] v0.1.3 | Windows x64
[BLoader DevTools] Author: Chlna6666
[BLoader DevTools] License: GPL-3.0-only (open source)
[BLoader DevTools] Source: https://github.com/Chlna6666/BLoader-DevTools
[BLoader DevTools] UI: in-process Win32 child + egui + D3D11
[BLoader DevTools] UI worker started; UI_READY will be logged after the first Present
[BLoader DevTools] UI_THREAD_STARTED; searching for Minecraft top-level HWND
[BLoader DevTools] GAME_HWND_FOUND hwnd=...
[BLoader DevTools] CHILD_WINDOW_CREATED hwnd=...
[BLoader DevTools] D3D11_DEVICE_READY; initializing egui frame
[BLoader DevTools] UI_READY: first D3D11 Present succeeded; press F8 to show/hide
```

如果只有 `native-load`、`preload-native` 等消息，而没有 `Loading BL Mod`，说明 Mod 清单类型仍然不正确。若有 `WAITING_FOR_GAME_HWND`，说明 UI 线程没有识别到可用的游戏窗口；若有 `UI_THREAD_FAILED` 或 `D3D11_PRESENT_FAILED`，请提供对应错误号/错误信息。

## 当前实现范围

- BL Mod v1 ABI 的 `bl_mod_main_v1` 和 `on_load/on_unload`；
- 初始化后创建独立 UI 线程，等待游戏 HWND，再创建 Win32 游戏子窗口；
- egui 0.35 + egui-directx11，独立 D3D11 Device/Swapchain，**启动时自动显示，无需按 F8**；
- 对 RDP 远程会话使用同进程顶层窗口；若游戏主窗口不属于当前 PID，3 秒内回退，不再无限等待；
- 游戏子窗口创建失败或其 Swapchain 初始化失败时自动尝试同进程顶层窗口；
- 硬件 D3D11 初始化失败时尝试 WARP 软件渲染，并记录显式诊断日志。
- AOB/十六进制离线测试、通配符匹配、复制特征；
- 包含 Memory、Disassembly、Version Migration、Hooks 等页面，但**目前尚未实现对游戏的内存扫描、断点和真实 Hook 检测**；
- 未安装额外 EXE；不 Hook Minecraft 原有 Present；无需独立服务进程。

### 已知限制

此版不是 RenderDragon Swapchain 内的叠加纹理，而是同一进程下的 Win32 子窗口。窗口化/无边框模式优先测试。远程桌面通常能显示顶层窗口，但**只捕获游戏 Swapchain 的直播/串流软件未必会捕获独立窗口或 Win32 子窗口**；这种情况需要进一步实现真正绘制进游戏渲染目标的 Overlay，不是 F8 问题。需要实测 D3D Swapchain 与游戏窗口遮挡次序、Raw Input、鼠标锁定、跨线程子窗口焦点、中文 IME、DPI、游戏退出与卸载。进程整体被暂停时，同进程 UI 也会暂停。

## 构建

在 Windows MSVC x64 Rust 环境：

```powershell
cargo test --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

输出：`target/x86_64-pc-windows-msvc/release/bloader_devtools.dll`。必须与 `package/manifest.json` 同目录安装为 BL Mod。

GitHub Actions 构建会同时校验 manifest，并提供已按 `mods/bloader.devtools/` 打包的可安装产物。构建通过不代表已经完成 Minecraft Windows 实机的窗口显示和卸载测试。

## 后续功能

先完成安装/显示/启动日志等可靠性测试，再添加只读扫描、寄存器快照、断点采样与跨版本自动特征迁移。调试实验应首先限定在授权的离线单人环境。

## 启动自动显示与远程验证

v0.1.3 在 BL Mod `on_load` 后启动 UI 线程，成功创建 Win32 窗口就立即 `ShowWindow``，无需任何热键。仍支持 F8 作为可选操作。RDP 会话在同一个 Minecraft 进程内创建顶层 DevTools 窗口；无法识别游戏 HWND 时等待最多 3 秒后回退。子窗口无法创建或 D3D11 初始化失败时也尝试顶层模式。

正常日志重点：`UI_THREAD_STARTED` → `GAME_HWND_FOUND` 或 `GAME_HWND_NOT_FOUND` / `REMOTE_SESSION_DETECTED` → `UI_WINDOW_CREATED` → `UI_WINDOW_SHOWN_BY_DEFAULT` → `UI_MODE_READY` → `UI_READY`。出现 `UI_THREAD_FAILED` 时根据 Win32/HRESULT 错误排查。如果日志达到 `UI_READY` 但远程串流看不到，请确认远程工具捕获的是整个桌面还是仅游戏画面。

## 0.1.3：中文界面与 AI MCP 测试（实验性）

- 中文工作台、系统 CJK 字体回退、深色/浅色主题、响应式工作台、原有 AOB 测试。
- 全部在 Minecraft 游戏进程的 DLL 中运行，不安装独立 EXE；从“设置与关于”手动开启/关闭本机 MCP 服务。
- 仅绑定 127.0.0.1 随机端口；32 字节随机 Bearer token 可由 DevTools 设置页复制；缺少 token 的连接拒绝。拒绝浏览器 Origin 头，阻止 DNS rebinding。**默认关闭，卸载时关闭。**
- MCP Streamable HTTP 的工具包括 window_info、capture_window、click_window；target 支持 devtools 和 game，点击坐标是相对客户区像素。
- 截图当前使用 Windows GDI PrintWindow，**不能保证 RenderDragon/D3D/UWP 游戏画面可用**；黑屏或失败会返回工具错误，之后需要实现 D3D 图形读回或 Windows Graphics Capture。
- 点击通过 Win32 窗口消息传送；Minecraft Raw Input 可能绕过此消息处理。不能根据“消息发送成功”判断游戏逻辑处理成功，必须重新截图验证。
- 需要在本机 Codex 或其他支持 MCP HTTP + 自定义 Authorization 请求头的客户端中填入 DevTools 页面显示的 MCP 地址和 token。**ChatGPT 云端无法直接访问你电脑的 127.0.0.1。**
- AI 识图由支持视觉的 MCP 客户端模型执行，DevTools 本身不做 OCR 或 LLM 推理。
- MCP 仅用于本人有权控制的离线/单人游戏测试，不应向公网暴露，也不建议在不受信任 Mod 或多人服务器中开启。

验证边界：GitHub Actions 只覆盖 Windows 编译、单元测试与发布打包；并不代表 MCP 游戏画面捕获、点击和实际 UI 显示已通过实机。
