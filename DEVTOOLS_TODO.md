# DevTools 功能与正确性路线图（0.3.2）
> 目标：完全由 DevTools.dll 实现原生调试与 AI 自动化；BLoader 只提供加载、卸载、日志。所有勾选以代码与 Windows 编译测试为依据，游戏实机结果单列记录。

## 当前已实现
- [x] 游戏进程内独立 Win32 UI 线程、egui D3D11 绘制；启动自动显示
- [x] 中文系统字体、深浅色配色、IDE 风格项目栏/多工具标签/地址检查器/控制台、面板显隐与 Ctrl+1…8 快捷导航
- [x] 有界扫描：可写/可读/可执行内存权限，起止地址，16–1024 MiB 预算；数值扫描、二次比较、取消
- [x] 修复 U64 精度、AOB 数值基线混用、取消筛选破坏候选、工作线程关闭、分页候选
- [x] 十六进制只读、iced-x86 反汇编、AOB/特征持久化、旧版与新版文件 AOB 对比
- [x] 地址检查器：读值、手动 compare-before-write、64 项定时监视以及本地持久化
- [x] DevTools DSL：scan、next、read、disasm、aob、assert、wait、write、reset。写操作单独授权；断言失败中断脚本
- [x] DevTools MCP：回环网卡随机口、Bearer 鉴权、UI 状态查询、UI 标签导航、UI D3D11 PNG 截图、实验性 Minecraft 截图及输入
- [x] 按 Bedrock/Minecraft 类与标题按需解析 HWND（避免一次性缓存），Windows CI Release DLL 构建
- [ ] Windows 实机下以上各功能的端到端验证（特别是多分辨率窗口、IME、Input、截图与卸载）

## P0：必须先闭合的可靠性
- [ ] 真实 Windows Minecraft 1.21/26.x 下测试加载、主窗口、RDP、F8 和子窗口的输入/焦点/IME 与 DPI 变化
- [ ] 独立的可执行 GUI 集成回归测试：自动启动、MCP 查询、切标签、截图、点击、核验结果
- [ ] 内存扫描目标选择器：模块/内存区域过滤、权限/大小图表、全范围游标及自适应扫描预算；当前预算是按地址升序收集，仍可能漏掉高地址游戏堆
- [ ] 结果基线与脚本统一事务、完整错误传播、读写审计记录与异常回滚/恢复协议
- [ ] CPU/GPU/内存遥测：空闲帧请求、截图频率、扫描尾延迟、窗口资源生命周期
- [x] 游戏 HWND 在前台时尝试 GDI 桌面合成截图，实验性 PrintWindow 回退；放宽 window_info/click 的截图大小限制
- [ ] 真实 RenderDragon 游戏帧捕获：WGC/后端特定 GPU 安全读回，不再依赖 PrintWindow/桌面截取；支持帧时间戳和分辨率代次

## 0.3.0 统一发现链路
- [x] Symbol Resolver：主 EXE 可执行页参考 AOB 搜索、唯一匹配与 x64 虚表索引解析；可选 ClientInstance 候选的只读 getter 入口检查
- [x] ECS Inspector：MEM_PRIVATE 可写内存容量与覆盖率诊断、跨区域采样；可选玩家 HUD XYZ 的 AABB + Vec3 位置双路径初筛
- [x] ECS Inspector：优先候选的指针反向引用查询、MSVC x64 RTTI 启发式 Actor/Player 类型线索
- [x] LocalPlayer Validator：空间/结构/引用/RTTI 分级证据，及连续行为采样筛选；空筛选不销毁上一轮快照，未经过 getter 校验不得假称已定位
- [x] UI 和 MCP：一键统一后台分析、覆盖率/引用报告、取消支持
- [x] ToolHelp 多模块清单和精确 SHA-256 离线 RVA 符号库，并支持可选本地 DbgHelp/PDB
- [x] 当前游戏 EXE 哈希匹配的 ECS 指针偏移配置 + 双向引用结构检查
- [ ] 多模块的签名自动生成/评分与兼容模块加载，当前仍需明确符号名和版本
- [ ] 从客户端实际 EnTT/EntityContext/Registry 证据抽取组件偏移，不假设 BDS 与客户端布局相同
- [x] 实验性生命周期观察器：精确模块 SHA-256/RVA/完整入口指令核验，显式本地操作才安装 update Hook
- [x] 回调只记录原子状态，调用原始 update trampoline；独立手动授权后才调用已配置 getter，并支持退休、清空和 3 秒新鲜度
- [x] 在 DevTools 后台线程用精确 ECS 布局验证刚捕获的 getter 候选：双向引用完整、对象快照未变化才报告结构一致
- [ ] 从当前零售版 Minecraft 精确确认 ClientInstance::update/getLocalPlayer 的 ABI，并完成真实 Windows 游戏（多版本）回归
- [x] 禁用时保留 trampoline 并 PIN 模块至进程退出，BL v1 不支持卸载否决；多线程快照代次/非 owner 线程跳过
- [ ] 多 ClientInstance/分屏、世界退出/换维度时的控制归属与 getter ABI 实机确认；不能保证热卸载
- [ ] 需要精确验证 EntityContext/PlayerComponent 的客户端控制归属，不能把 getter 返回地址直接变成稳定 SDK 句柄
- [ ] 根据客户端游戏线程和真实 ECS 注册表验证 PlayerComponent/ActorOwnerComponent，取得真正 LocalPlayer*
- [ ] 反引用阶段由受信任的组件偏移数据驱动；避免当前启发式 RTTI 假阳性
- [ ] 真实 Minecraft 本机、远程会话、不同构建的端到端数据验证

## 本地玩家（LocalPlayer）统一定位工作区
- [x] 新增实体几何初筛：AABB [minXYZ,maxXYZ]、宽高公差、可选世界坐标、私有堆优先分段扫描与走动/跳跃二次筛选
- [x] AABB 线框示意、候选分页、地址复制及十六进制检查，不把碰撞箱候选伪装为 Actor/LocalPlayer 身份
- [ ] 由 AABB 候选反推所属 Actor 对象/组件及与客户端受控实体对应关系，加入视角和生命周期交叉验证
- [ ] 不同玩家姿态/3D 碰撞形态识别、非 AABB 排列和 ECS Transform/Bounds 格式适配
- [x] 专用 LocalPlayer 工作区、参考 AOB 游戏 EXE 可执行区查找、只读虚表索引解码
- [x] 已知 ClientInstance 对象或指针槽的只读验证；手动成员偏移探测 / 虚表入口候选
- [x] 游戏主 EXE SHA-256 绑定的候选规则保存（无运行时绝对指针），标注 candidate-only
- [ ] 自动捕获 ClientInstance 的生命周期入口，并在正确游戏线程安全调用 getter
- [ ] 进入/退出世界和重新连接的多版本对象代次与地址失效验证
- [ ] 跨版本 CFG/ABI 的自动验证与可由普通 Mod 使用的生成 SDK
- [ ] 历史 Flarial 参考模式不保证当前 Bedrock 版本存在；不能用其宣称已经识别玩家

## P1：原生调试能力
- [ ] 指针链与指针扫描，引用关系、模块基址/RVA，读写观察与变化历史
- [ ] 进程内线程列表、CONTEXT、硬件断点（DR0–DR3）、VEH 异常分发、无暂停捕获模式；全局暂停需保留外部可操作通道
- [ ] DevTools 自有 Hook 注册、物理入口独占和回调优先级；其他私有 Mod Hook 只能启发式检测、不能保证完整归因
- [ ] 符号数据库、反汇编控制流图与调用链、AOB 自动生成的重定位/交叉引用验证
- [ ] 脚本编辑器：语法高亮、诊断区、可命名多文件、调试历史、测试断言报告；CE AutoAssembler 是单独实现，不应假称当前 DSL 已兼容
- [x] 拖拽左右分隔条与底部控制台高度、持久化窗格尺寸/显示状态、视图菜单重置
- [ ] 完整可停靠布局：标签拆分、独立浮动工具窗口的可拖拽停靠与分屏树；当前是可调整尺寸的 IDEA 风格固定区块，并非完整 IntelliJ Docking

## P2：跨版本与生态
- [ ] 版本指纹数据库、x86-64 函数聚类/CFG 多候选评分、差分及人工确认的 ABI 校验
- [ ] SDK 类型信息和稳定公共 Mod 接口（由 DevTools 自行生产、可选择另一个独立 Mod 实现运行时）
- [ ] 多 Mod Hook 冲突可视化、相互调用/优先级/所有者探针与安全禁用机制
- [ ] 发布隔离开发者特性、崩溃保护、权限开关和社区特征包导入导出

## 验收规则
1. Windows MSVC cargo test + Release DLL + BL Mod 安装包上传成功。
2. 必须区别编译通过、离线单测通过与真实游戏操作通过。
3. DevTools 不能将扫描、Hook、MCP 或脚本执行依赖强加给 BLoader Core。
4. 所有扫描、等待和深度分析在后台线程完成；取消需无死锁、无泄漏、不会误写游戏数据。
5. 对无法验证的特性明确标注“实验性/未实现”，不能展示伪数据。

## 0.3.2+：游戏窗口阻塞与 ClientInstance 验证

- [x] 默认创建独立进程内 **WS_OVERLAPPEDWINDOW 顶层工具窗口**；不再将 D3D11 SwapChain 的 WS_CHILD 挂到游戏 Bedrock HWND，避免直接覆盖和接管 RenderDragon 输入。
- [x] 启动采用 SW_SHOWNOACTIVATE，避免自动夺取 Minecraft 前台焦点；F8 显示/隐藏只操作 DevTools 自己的 HWND；UI_PRESENT_READY 不宣称窗口像素一定可见。
- [x] 生命周期新增只读 `InspectInstance`：读取已人工授权 update 回调中的 `this` 首指针、虚表 slot0、映射模块与页面可执行属性，复核快照代次，并统计对象切换 / ready 参数变化。
- [ ] **必须实机验收**：Minecraft 1.26.40.5 的新独立窗口可见、可最小化、不会阻塞游戏帧；多显示器、DX11/DX12、F8、复制/拖拽输入、关闭再显示。
- [ ] 独立 UI 的真实 HWND 可见性与 RenderDragon 合成验证；零售客户端的 update/getLocalPlayer 调用 ABI 与本地玩家生命周期仍未被证明。

