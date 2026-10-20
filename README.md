# BLoader DevTools

Minecraft Bedrock 原生 Mod 开发工具。**纯 DLL**，通过 BLoader 的 BL Mod ABI v1 加载，不启动独立 EXE。

## 首版界面架构

- BLoader 在初始化 BL Mod 后调用 on_load；只创建轻量控制线程，不在 DllMain 初始化 GUI。
- 工作线程寻找同一 PID 的 Minecraft 主窗口，创建 **Win32 子窗口**（窗口仍属于游戏进程），独立处理 Win32 消息、egui UI 和 D3D11 绘制。
- 使用原生 Win32 消息循环 + egui 0.35 + egui-directx11，独立 D3D11 Device/Swapchain，不改写游戏 Present，不依赖游戏 D3D11/D3D12 设备；不初始化 winit，避免其 Raw Input 注册与 Minecraft 冲突。
- **F8** 切换子窗口；关闭按钮隐藏 UI；卸载 Mod 时通知并等待 UI 线程退出。
- 当前提供可操作的多个工具页面与离线 AOB 匹配验证。内存扫描、硬件断点、注入 Hook 和跨版本迁移仍是后续阶段，界面明确标注未实现，不会写游戏内存。

### 已知限制

此版使用同进程子窗口而非 RenderDragon 画面内纹理合成。在窗口化/无边框模式下试用；独占全屏、Raw Input、游戏鼠标锁定、跨线程子窗口焦点、中文 IME（当前仅基础 WM_CHAR）、鼠标 Raw Input 并行路径和多显示器 DPI 需要 Windows 实机验证。游戏进程整体被调试器暂停时，同进程 UI 一样会暂停。子窗口有自己的消息线程，但不能突破进程级暂停。

## 构建

Windows 11 / Visual Studio C++ 构建工具（MSVC x64）+ Rust stable：

~~~powershell
rustup target add x86_64-pc-windows-msvc
cargo test --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
~~~

产物为 target/x86_64-pc-windows-msvc/release/bloader_devtools.dll。将 DLL 作为 BLoader 的 BL Mod 部署，入口导出为 bl_mod_main_v1。Cargo 的 package.metadata.bl 声明用于配套打包工具读取。

项目当前不包含 EXE、后台外部服务或独立进程。无 GUI 时不需要操作游戏 GPU 渲染链路。

**构建验证状态：** GitHub Actions Windows MSVC 构建已通过：2 项单元测试通过，Release `bloader_devtools.dll` 构建成功且产物已上传至 [Windows MSVC DLL #39459235451](https://github.com/Chlna6666/BLoader-DevTools/actions/runs/39459235451)。本次仅验证编译与离线测试，**尚未完成 Minecraft Windows 实机运行、F8 输入、显示与安全卸载验证**，不能将其视为已验证游戏内可用的发布版本。

## 下一步

对接 BLoader 的稳定 Hook 服务；以可取消后台任务实现只读内存扫描；实现指令分析与经验证的特征档案；跨版本迁移只发布有明确构建指纹的适配数据。开发模式首先限定为用户授权的离线/单人测试环境。
