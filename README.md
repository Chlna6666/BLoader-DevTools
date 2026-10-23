# BLoader DevTools

版本：0.3.2 · 作者：Chlna6666 · GPL-3.0-only

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


## 0.3.2 ClientInstance 游戏线程生命周期观察（默认关闭）

参考 2026-10-19 更新的 [b01dev/MCBE_DX12_ModBase](https://github.com/b01dev/MCBE_DX12_ModBase) 中 `ClientInstance::update(ClientInstance*, bool)` 回调获取 `this` 的方式。本功能为**经人工确认的目标构建专用实验性设施**，不是自动兼容 Minecraft 26.52 / 1.21 的万能偏移。参考项目的函数 ABI 不保证对当前所有版本适用。

新增 `src/lifecycle.rs`，支持四层限制：

1. **版本身份**：本地配置中的模块名、SHA-256、RVA 必须完全匹配实际 Windows 进程模块。
2. **代码完整性**：要求 12–48 个完整机器码字节，使用 iced-x86 检查整条指令边界、可执行页及函数入口当前字节；拒绝已明显存在 JMP/INT3 补丁的入口。其他 Mod 仍可能通过非入口补丁 Hook，不能保证排除一切 Hook 冲突。
3. **显式 UI 授权**：初始状态不安装；用户先勾选风险确认，再点击「启用 update 观察」。观察回调仅通过原子变量记录真实游戏更新线程、ClientInstance 候选、调用次数、最近 3 秒活跃状态；不分配、扫描内存、写日志或者操作 egui。
4. **getter 独立授权**：需要在配置中另外给出同样严格验证的 getter 模块/入口字节与 `client_get_local_player_this_to_ptr` ABI。点击「单独启用 getter 调用」后才会在真实 `update` 游戏线程、原始 update 结束、ready 标志满足条件时调用目标 getter。用户必须先反汇编确认返回类型与 ABI，否则可能导致游戏崩溃。所得指针标记为 candidate-only。 增加「验证 Getter 对象 ECS 关系」按钮（或 MCP 的 `devtools_lifecycle(action="validate_player")`）：仅在最近 3 秒的真实 update/getter 返回值有效且对应游戏 EXE 的 ecs_layouts.json 精确匹配时，在后台线程读回 ActorOwner、PlayerComponent、ShapeComponent 和组件 backref。检查期间如果观察到对象更换就拒绝结果。这是结构复核而不是完整的本地控制身份和跨世界生命周期验证。

配置文件：`%LOCALAPPDATA%\BLoader-DevTools\client_lifecycle.json`。结构说明：

```json
{
  "schema": 1,
  "update": {
    "module": "Minecraft.Windows.exe",
    "sha256": "替换为真实模块完整64位sha256",
    "rva": "0x人工验证的UpdateRVA",
    "abi": "client_update_this_bool_to_bool",
    "entry_bytes": "用当前函数前12至48个完整字节的空格分隔十六进制替换"
  },
  "getter": {
    "module": "Minecraft.Windows.exe",
    "sha256": "替换为真实模块完整64位sha256",
    "rva": "0x人工验证的GetterRVA",
    "abi": "client_get_local_player_this_to_ptr",
    "entry_bytes": "用当前getter前12至48个完整字节的空格分隔十六进制替换"
  }
}
```

上述内容是**文档模板，不是可运行的真实版本配置**。getter 可省略或设为 null，此时只有 ClientInstance 观察功能。所有输入必须基于当前游戏 PE/PDB、汇编和实机确认。未知版本不会静默采用 Flarial 或其他客户端项目的旧偏移。

通过 DevTools UI 的「本地玩家定位 → 游戏线程观察器」执行：校验配置 → 启用 update 观察 → 进入世界验证 callback/thread/this → （单独确认 getter ABI 后）启用 getter → 观察返回值 → 停止并清除。MCP `devtools_lifecycle(action="status"|"verify"|"stop")` 只能查询、核验或停止，不能远程启动 Hook / 启用 getter。启用后卸载 DLL 前必须通过本地「停止并清除」正常退休 trampoline；若返回错误，**不要热卸载**。

当前**还没完成**：从当前零售版 Minecraft 自动发现并验证 `ClientInstance::update` 的签名/ABI；对真实 PlayerComponent 的 Client 控制归属核验；分屏、世界卸载和对象复用的强代次句柄；多 Mod 共存 Hook 冲突归因。该观察器并不直接对其他 Mod 提供持久 `LocalPlayer*` ABI。


## 0.3.1 多模块符号解析与版本化 ECS 校验

参考长期维护的 LeviLamina、Flarial 和近期 26.52 客户端的 MCBE_DX12_ModBase。借鉴符号缓存、游戏 update 中捕获 ClientInstance this、组件关系验证等方法；不复制未验证偏移。

- DevTools 独立枚举进程的各个模块，计算原始模块文件 SHA-256，仅加载完全相同版本的本地 RVA 符号表。
- DbgHelp/PDB 查询为可选开关，仅使用模块所在文件夹的本地符号，不联网。
- LocalPlayer 页面可以刷新模块目录，填写模块名称与符号，并查看 RVA、原始 VA、来源和 SHA-256。
- ECS 校验仅加载与 Minecraft EXE SHA-256 完全匹配的组件指针布局，核实 Actor / ActorOwnerComponent / PlayerComponent / ShapeComponent 的双向关系；仍不证明本机 LocalPlayer 身份。
- 目前没有启用对游戏 ClientInstance::update 的自动 Hook 或调用 getter。必须验证目标游戏构建、代码 ABI 和游戏线程、卸载生命周期才能安全执行。

符号库：%LOCALAPPDATA%/BLoader-DevTools/symbol_profiles.json。格式：

~~~json
{"schema":1,"modules":[{"name":"Minecraft.Windows.exe","sha256":"请使用游戏真实64字符sha256","symbols":{"ClientInstance::getLocalPlayer":"0x已验证RVA"}}]}
~~~

以上字符串只是配置结构说明，不是可直接导入的真实符号/偏移，项目拒绝长度不正确的 SHA-256。地址必须经真实目标版本验证。

ECS 布局：%LOCALAPPDATA%/BLoader-DevTools/ecs_layouts.json。字段包括 module_sha256、actor_owner_ptr、player_component_ptr、aabb_component_ptr、owner_backref、player_backref 和 aabb_offset。所有偏移必须来自特定客户端构建的可信证据，不能直接使用服务器版本的 ECS 布局。

参考：https://github.com/LiteLDev/LeviLamina · https://github.com/flarialmc/dll-oss · https://github.com/b01dev/MCBE_DX12_ModBase

## 0.3.0 统一本地玩家分析链路（实验性）

针对“碰撞箱候选=0，扫描=128 MiB”的反馈，新增独立 DevTools 后台任务：Symbol Resolver → ECS Inspector → LocalPlayer Validator。在「本地玩家定位」页点击「开始统一分析」，或使用本机 MCP：

~~~text
devtools_player_discover(x=玩家X, y=玩家脚底Y, z=玩家Z, radius=3, budget_mib=256)
devtools_player_report()
# 玩家在游戏里走动/跳跃后：
devtools_player_refine(motion="horizontal")
devtools_player_report()
~~~

**第一阶段（Symbol Resolver）**：针对进程主 EXE 的可执行页扫描旧版 getLocalPlayer 参考 AOB，核查唯一匹配及指令编码，并解析虚表索引。它不是 PDB 自动解析，也不能证明新的客户端版本存在相同 getter。已知 ClientInstance 指针可作为可选输入，用于进一步只读检查 getter 入口。

**第二阶段（ECS Inspector）**：枚举真实可写 MEM_PRIVATE 区域，以有限预算跨区域采样，并记录扫描 MiB / 总可读私有区 MiB 及覆盖百分比。尝试 24 字节 AABB，同时在提供玩家世界坐标时匹配独立 Vec3 浮点位置结构，不再假设所有客户端都把 AABB 按六个 float32 连续存放。选择最近的空间候选后，查找引用该内存位置附近结构的指针槽，启发式检查邻近 MSVC C++ RTTI。

**第三阶段（LocalPlayer Validator）**：按空间距离、形状、指针引用和 RTTI 给出解释性候选与证据。支持首次分析后采样玩家动作，选择「水平走动」「跳跃」等行为进行再次验证，对上次的 AABB/Vec3 地址读取新位置、缩小候选；如果本次筛选为空则保留原快照供重试。即使 RTTI 包含 Player，也仍缺少 ClientInstance::getLocalPlayer() 的正确游戏线程返回值验证，不能标记为已确认 LocalPlayer，也不能输出可调用的 Actor* 给普通 Mod。引用链和 RTTI 不一定存在。此阶段目前只提供只读启发式校验，不调用游戏函数或安装 Hook。

为什么原扫描可能为 0：128 MiB 只是有限读取预算，不是整个游戏堆；原始算法按可读区域排序抽样，且只匹配 AABB 连续 minXYZ,maxXYZ 布局。某些构建把位置、尺寸和 AABB 放在不同 ECS 组件，或使用不同对象姿态。建议在游戏显示坐标后填入精确 XYZ，使工具同时进行 Vec3 检索。提高预算不等于必然能定位玩家。

这个统一工具完全由 DevTools DLL 自己维护，不修改 BLoader，也不需要独立 EXE。仍待完成的关键 P0：真实客户端符号来源（PDB/签名数据库）、确定的 ActorOwner/PlayerComponent 布局、在游戏线程安全执行 getter 及进入/退出世界的对象生命周期验证。

## 0.2.3 玩家碰撞箱 / 3D 实体候选快速查找

「本地玩家定位」页面新增**无需 ClientInstance 地址的几何特征初筛**：假设 AABB 按 6 个连续 float32 存储，顺序为 min(x,y,z)、max(x,y,z)，站立玩家默认宽/高/深 = 0.6 / 1.8 / 0.6（具体版本、姿态或内部布局可以不同）。支持自定义宽度、高度、容差，以及可选的游戏世界坐标 X/Y/Z（以脚底为 Y）和距离半径。



本机 MCP AI 测试工具（需要在设置中主动开启 MCP）：
- `devtools_collision_scan`：指定宽、高、容差、可选 x/y/z 脚底位置与 radius，以及扫描预算 budget_mib；仅提交后台扫描任务。
- `devtools_collision_results`：轮询 busy 状态和最多 50 条候选 AABB 的中心坐标、地址与样本数量。
- `devtools_collision_refine(motion="horizontal")`：本人在游戏里完成走动/跳跃后，按旧、新 AABB 位置变化筛选候选；motion 可选 horizontal、jumped、moved、stationary。

首次扫描在 DevTools 专用后台线程中优先搜索私有可写内存区域；按照「内存扫描」设置的地址范围和 MiB 预算分段抽样。默认预算通常无法覆盖整个游戏堆，未命中时应按实际内存分布调整预算/范围；游戏不会为查找自动停止渲染。

候选筛选：首先静止时扫描；再在世界里走几步，按「水平走动」筛选变化了的 3D AABB；再在跳跃途中、*落地前* 按「跳跃/垂直移动」进一步筛选。每轮对同一内存地址再次读取 24 字节，记录中心位置、采样次数和移动累计距离。可以分页、复制 AABB 数据地址、打开十六进制查看，还可显示 AABB 线框的示意投影。

**限制：** AABB 命中只说明疑似实体尺寸数据；其他玩家、NPC、模型缓存、物理临时对象也可能命中。线框只是对内存数据绘制的几何图，并非游戏 3D 模型或 LocalPlayer 身份证明。找到 AABB 不等于找到 Actor*；要识别真正的本地玩家，仍须追踪所有者、在正确游戏线程获取 ClientInstance/LocalPlayer 并验证对象生命周期。此功能仅读，不写入游戏内存。


## 0.2.2 本地玩家定位

新增「本地玩家定位」页，MCP 也支持 `devtools_navigate(tab="localplayer")`。定位采用 `ClientInstance → getLocalPlayer() → LocalPlayer` 的版本化候选路径；与 BLoader Game SDK 无关。

- 快速在游戏主 EXE 可执行区匹配历史参考 `getLocalPlayerIndex` AOB。仅唯一匹配时解析候选虚表索引，不直接执行虚函数。
- 手动提供 ClientInstance 的运行时指针或持有指针的地址槽，验证虚表及入口；对于确知旧版成员偏移的版本可只读探测玩家指针。
- 导出候选定位规则绑定当前游戏 EXE SHA-256 和访问方式；不保存 ASLR 绝对内存地址，始终标记 `candidate-only`，游戏更新后不得自动沿用旧构建结果。
- 没有 ClientInstance 对象来源时，虚表索引本身不足以定位 LocalPlayer；需要额外的游戏生命周期事件获取 this 指针。当前没有自动调用未验证的方法，也没有承诺进入世界后自动识别。
- 玩家进入/退出世界、重新连接、加载屏幕和版本变化应分别进行实机校验，不能将可读的 C++ vptr 认定为类型证明。

## 0.2.1 游戏窗口截图与可调整工作台

**IDE 面板**：拖拽左右两条分隔线可调整项目栏和地址检查器宽度；拖拽编辑区与底部控制台之间的水平分隔线可调整控制台高度。顶部「视图」菜单控制面板显隐和重置默认布局；尺寸与显隐状态保存于 %LOCALAPPDATA%\BLoader-DevTools\layout.json，下次启动恢复。窄窗口下检查器采用浮动窗口。该布局还不是 IntelliJ 那种任意停靠树和标签拆分。

**游戏画面 MCP 截图**：`capture_window(target="game",mode="auto")` 在 Minecraft 处于前台且可见时先尝试捕获 Windows *桌面合成后的客户区画面*；不可用时退回实验性 `PrintWindow`。可用 `mode="desktop"` 或 `mode="printwindow"` 强制对比方法。对于 4K 等高分辨率游戏窗口，桌面合成截图会按像素预算缩小 PNG，但 `window_info` 和 `click_window` 不再因窗口超过 1920×1080 而被拒绝。返回文本会分别标注原客户区分辨率与输出 PNG 分辨率，点击依然使用**原始游戏客户区坐标**。

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

## 0.3.2+ 生命周期安全与跨版本符号验证

**重要：第一次成功启用 ClientInstance Hook 后，DevTools DLL 会使用 Windows `GetModuleHandleExW(PIN | FROM_ADDRESS)` 固定至 Minecraft 进程结束。** 这是明确的生命周期取舍，并非普通的可热卸载 Hook：BLoader BL v1 的 `on_unload()` 没有返回值，不能拒绝宿主的模块卸载。仅检查回调计数为 0 也无法排除其他线程已取到旧 Detour 分支但尚未进入函数。

- `stop` 禁止新采集、禁用游戏入口补丁并尝试排空当前回调。已经分配的 trampoline 不会通过 `remove_hook` 或 `uninitialize` 释放，DLL 不会热卸载；关闭游戏才彻底回收。
- 停止后可在**同一版本和目标 RVA** 重新启用；不允许将仍被保留的 trampoline 复用到另一目标，必须重启游戏。若禁用失败或回调超时，保持保守状态并提示禁止热替换。
- 仅首个观察到的 update 线程可发布快照和执行已单独授权的 getter；其他线程跳过采集并计数。快照使用代次一致性检查，检测内存复核期间发生的对象更新；这不是全局暂停世界或锁定 Actor 生命周期。
- `client_lifecycle.json` 中的 `abi` 名称、模块 SHA-256、函数 RVA 和入口字节属于**人工审核输入**，无法自动证明实际 C++ ABI。实际 ClientInstance::update/getLocalPlayer 形参、返回值与虚函数入口，仍需按零售客户端构建进行逆向和实机验证。严禁直接套用 BDS、其他 Minecraft 版本或社区示例的偏移。
- 所有地址继续作为 `candidate-only`，包括已通过三组件结构检查的 getter 返回值。进入/退出世界、换维度、重连、分屏及生命周期代次仍属待测。

### 可参考的外部实现（只读证据来源，非可直接调用的 ABI）

- [LeviLamina](https://github.com/LiteLDev/LeviLamina)：客户端接口头文件提供 `ClientInstance`/虚方法的结构线索，但不能把 BDS 侧符号/组件偏移直接用于 Windows 客户端。
- [Flarial dll-oss](https://github.com/flarialmc/dll-oss)：版本化 signature/offset 映射及 ClientInstance 封装；符号命名或 C++ 声明不是本地版本的地址/调用约定证明。
- [MCBE_DX12_ModBase](https://github.com/b01dev/MCBE_DX12_ModBase)：模式解析、Hook 和运行时 SDK 的实现参考，不把其特定客户端版本中的签名导入默认启用路径。



## 进程内存完整遍历（实验性）

统一 LocalPlayer 分析的扫描预算设为 **0** 时，DevTools DLL 使用 `VirtualQuery + ReadProcessMemory(GetCurrentProcess())` 分块遍历本进程所有已提交可写页（包括 MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE），不再限制 1024 MiB。可取消、块缓存复用；命中超出 1536 项时继续遍历并均匀保留代表性样本。使用非零 MiB 仍为抽样模式。若版本化符号和 ECS 组件身份缺失，遍历全部进程内存也不能确认 LocalPlayer。

碰撞箱独立入口也可选择“完整进程扫描”，MCP `devtools_collision_scan(budget_mib=0)` 同样有效；普通数值扫描仍保留 MiB 上限。保留候选容量不等于真实命中总数，所有命中均只是空间特征，绝不等同于 LocalPlayer 身份。


### 游戏模块代码特征（实验性）

统一玩家定位现在只读扫描主模块 PE .text，分别报告 update / getLocalPlayer 两种参考 AOB 的候选 RVA 和命中数量。来源：b01dev/MCBE_DX12_ModBase，src/minecraft/bedrock_memory.h（MIT，© 2026 Binary01）。此功能不会自动 Hook、调用 getter 或认定本地玩家。旧版本特征可能不适用于当前 SHA-256 的 Minecraft 客户端；0 命中时须以实机二进制继续分析。


### 控制台和反汇编安全性

Win32 左键拖动时临时 SetCapture/ReleaseCapture，保证光标越过窗口边缘仍能继续产生鼠标移动事件；egui 控制台接近边缘拖选会持续滚动，松开后停止，选中后可 Ctrl+C 或复制全部。内存页会通过 VirtualQuery 标示保护属性；对不可执行堆/私有页拒绝反汇编，避免把包含指针的对象数据误解释成 x64 指令。


### DevTools 默认窗口与只读 ClientInstance 数据

UI 是游戏进程内部单独的原生顶层窗口（不是嵌入 Bedrock 客户端区域的子窗口，也没有外部 EXE），采用无焦点抢占的首次显示。成功的 D3D11 Present 仅代表渲染调用完成；不代表操作系统合成、游戏输入和前台可见性已在真实客户端验证。

在本地 UI 审核并授权精确 SHA-256/ABI 的 update Hook 后，“只读检查 ClientInstance this / 虚表”可列出当前回调的临时指针、虚表归属及变化计数。该操作本身不执行任何 C++ 虚函数、不使用 EnTT，也不将候选对象当作已确认 LocalPlayer。
