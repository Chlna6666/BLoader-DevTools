# BLoader DevTools

版本：0.2.1 · 作者：Chlna6666 · GPL-3.0-only

项目：https://github.com/Chlna6666/BLoader-DevTools

Minecraft Bedrock 进程内的独立原生 Mod 开发工作台。**BLoader 只负责 BL Mod 的加载、卸载和宿主日志。内存扫描、反汇编、脚本、特征码、模块检查和 MCP 都在 DevTools DLL 内实现。** 不需要 DevTools.exe，不修改 BLoader Core。

## 安装

从 [Windows 构建](https://github.com/Chlna6666/BLoader-DevTools/actions/workflows/windows-build.yml) 下载包含 manifest.json 与 bloader_devtools.dll 的 bloader-devtools-windows-x64 安装包：

~~~text
Minecraft版本目录/
└── mods/
    └── bloader.devtools/
        ├── manifest.json        # type = BL
        └── bloader_devtools.dll
~~~

**不能只放 DLL。** BLoader 对裸 DLL 使用 preload-native 加载方式，不调用 BL Mod 的 on_load。请删除此前自动创建的 mods/bloader_devtools 旧包。

DevTools 启动时自动显示 egui UI。F8 为可选显隐热键。UI 是游戏进程内 Win32 子窗口，远程桌面或 UWP 宿主无法作为父窗口时使用同进程顶层窗口；均不创建独立 EXE。

## 0.2.0 IDEA 风格工作区

- 左侧项目栏：编辑器工具导航、已保存的特征规则。
- 中央标签页：内存扫描、十六进制、反汇编、AOB、脚本、版本对比、模块与 Hook 线索、设置。
- 右侧检查器：地址、数据类型、预期旧值和新值，明确授权后执行 compare-before-write。
- 底部控制台：任务执行和错误记录。扫描在线程池之外的独立后台工作线程执行，支持用户取消，游戏渲染线程不做内存扫描。

功能与边界：

| 模块 | 进展 |
|---|---|
| 扫描与变化筛选 | 已实现 U8/U32/U64/F32/F64；精确值/变化/不变/增加/减少；当前限前 128 MiB 的可读内存及 8192 条结果 |
| 十六进制 | 已实现按指定地址读取与 ASCII 展示 |
| 反汇编 | 已实现 iced-x86 的 64 位指令解码，不修改代码 |
| AOB | 离线样本匹配、进程内搜索、复制和本地保存 |
| 数据修改 | 已实现手动旧值验证，仅修改可写数据页；没有任意代码补丁 |
| 脚本实验室 | 已实现受限 CE 风格 DSL，后台执行；写入需要本轮显式启用 |
| 模块 / Hook 检查 | 已实现进程模块列表和入口 JMP/INT3 启发式检查；不能可靠判断所有第三方私有 Hook 的所有者 |
| 版本迁移 | 支持对两个本地二进制按 AOB 比较文件偏移；尚未实现自动 CFG/语义/ABI 恢复 |
| 暂停断点 / 单步调试 | 尚未实现，不能把现有反汇编冒充完整调试器 |

脚本支持最多 40 条命令，不允许循环、调用任意 OS 接口或执行机器码：

~~~text
scan f32 90
next changed
# disasm 0x7FF600001000 24
# aob 48 8B 05 ?? ?? ?? ??
# write 0x7FF600001000 f32 90 65
~~~

write 需要显式勾选当前运行的写入权限，并指定预期旧值。如果扫描结果已变化，写入会拒绝；不会自动更改页面权限或修补可执行代码。工程脚本与特征数据库保存至 %LOCALAPPDATA%\BLoader-DevTools\ 。

## 0.2.x 工作台与调试功能增强

- 内存扫描区间支持输入起止十六进制地址，权限选择“可写数据 / 全部可读 / 可执行代码”，可配置 16–1024 MiB 扫描预算；这些是**扫描预算**，并不代表会无条件扫描整个 Minecraft 进程。
- 扫描结果按每页 100 条展示；支持数值筛选、取消任务和避免 U64 大整数精度丢失；AOB 结果不再混成数值基线。
- 地址检查器新增最多 64 个实时监视项，700ms 后台刷新；监视表保存在 `%LOCALAPPDATA%\\BLoader-DevTools\\watches.json`，支持重启恢复。
- IDE 工作台增加显隐项目栏、检查器、控制台，窄窗口中检查器自动改为浮动窗口；按 Ctrl+1…8 可切换八个工具标签（前提是 DevTools 接收到按键）。
- CE 风格**受限 DSL**支持 `assert 0x地址 f32 90`、`wait 200`、`write 0x地址 f32 90 65`，其中 wait 上限单次 2000ms，assert 失败停止后续写入。脚本提供单独的语法验证按钮。
- MCP 新增 `devtools_state` 与 `devtools_navigate(tab="script")`：直接和 DevTools UI 线程交互，返回真实状态、切换工具页，避免依赖不可靠的后台点击。
- 特征数据库写回改用 Windows 文件替换机制，避免第二次保存已有特征时文件重名失败。
- 仍待实现完全可拖拽的 IntelliJ IDEA 停靠面板、CE AutoAssembler、硬件断点、指针扫描、真正 RenderDragon 帧捕获与跨版本 CFG/ABI 迁移；详见 [DEVTOOLS_TODO.md](DEVTOOLS_TODO.md)。


## 0.2.1 游戏窗口截图与可调整工作台

**IDE 面板**：拖拽左右两条分隔线可调整项目栏和地址检查器宽度；拖拽编辑区与底部控制台之间的水平分隔线可调整控制台高度。顶部「视图」菜单控制面板显隐和重置默认布局；尺寸与显隐状态保存于 %LOCALAPPDATA%\BLoader-DevTools\layout.json，下次启动恢复。窄窗口下检查器采用浮动窗口。该布局还不是 IntelliJ 那种任意停靠树和标签拆分。

**游戏画面 MCP 截图**：\`capture_window(target="game",mode="auto")\` 在 Minecraft 处于前台且可见时先尝试捕获 Windows *桌面合成后的客户区画面*；不可用时退回实验性 \`PrintWindow\`。可用 \`mode="desktop"\` 或 \`mode="printwindow"\` 强制对比方法。对于 4K 等高分辨率游戏窗口，桌面合成截图会按像素预算缩小 PNG，但 \`window_info\` 和 \`click_window\` 不再因窗口超过 1920×1080 而被拒绝。返回文本会分别标注原客户区分辨率与输出 PNG 分辨率，点击依然使用**原始游戏客户区坐标**。

桌面合成画面**不是游戏 RenderDragon 内部 Backbuffer**；前台窗口被遮挡、特殊全屏、远程串流仅捕获游戏画面、桌面 DPI 配置等情况下，图片可能不完整甚至失败。真正的 Windows Graphics Capture / DXGI 纹理安全读回仍是后续任务，不将这一回退称为完整游戏 GPU 截图。


## MCP 与游戏窗口修复

MCP 默认关闭，在 DevTools 设置页手动开启，只监听 127.0.0.1，使用随机 Bearer token。连接方式见设置页；云端 ChatGPT 不能直接访问本机回环地址。

- window_info(target=game) 每次重新枚举 class=Bedrock、title=Minecraft 等有效窗口，支持属于其他 UWP 宿主 PID 的 HWND。返回句柄、PID、类名、标题与客户区大小，不再使用启动时的一次性过期缓存。
- capture_window(target=devtools) 使用 DevTools 的 D3D11 GPU staging 读回生成 PNG。
- capture_window(target=game) 先尝试前台可见桌面合成截图，后退为实验性 PrintWindow，**不保证 RenderDragon/DX11/DX12/UWP 画面正确**；黑屏作为失败处理。完整游戏帧捕获仍需后续 WGC 或安全的 GPU 读回通道。
- click_window(target=game,x=...,y=...) 默认使用 SendInput 模拟前台真实鼠标操作：尝试激活游戏、将客户区坐标转换为屏幕位置，再发送鼠标按下和释放。
- click_window(target=game,mode=message,x=...,y=...) 使用旧版 PostMessage，便于比较 Raw Input 与 Win32 消息；游戏可能忽略此模式。
- click_window(target=devtools,x=...,y=...) 默认使用 Win32 消息。

**SendInput 只针对当前交互桌面的前台窗口，会改变真实桌面光标。** RDP 权限、UIPI、特殊全屏或游戏 Raw Input 可能限制其效果。调用结果只代表已提交，不代表游戏已处理；必须重新截屏/检查游戏状态确认。仅在授权的离线测试中开启自动点击，不要将 MCP 暴露到公网。

## 编译与校验

~~~powershell
cargo test --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
~~~

CI 对 Windows x64/MSVC 进行单元测试、Release DLL 构建并上传完整 BL Mod 安装包。**编译通过不等于 Minecraft 实机中的内存扫描、窗口捕获和点击验证通过。**

正式发布前仍需验证 Windows 原生显示、远程 RDP、UI 中文 IME、游戏窗口生命周期、读取与写入策略、模块卸载线程回收和游戏帧捕获。
