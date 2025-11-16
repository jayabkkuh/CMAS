# 多代理 CTF 框架中文说明

## 项目概览

- 项目提供面向 macOS 的多代理 Capture-The-Flag（CTF）协作框架，聚焦逆向与综合攻防场景。
- 入口脚本 `main.py` 负责解析 CLI 参数、加载配置与 API 凭据，并创建 `MissionController` 启动整条任务流水线。
- 框架围绕 Agentscope 代理体系构建，所有操作与对话都会记录到 Mission 目录中，便于赛后复盘与审计。
- 输出目录按 Mission ID 划分，包含命令日志、证据卡、对话记录以及最终报告。

## 工作流分阶段

每轮任务由 `MissionController.run` 驱动（`framework/controller.py`），默认最多 3 轮。单轮流程：

1. **侦察** – `DetectiveAgent` 执行 `config.detective_commands` 中定义的工具链命令（`agents/detective.py`），收集静态信息并生成 `EvidenceCard`。
2. **规划** – `StrategistAgent` 调用 LLM 综合证据与技能册，产出 `TaskPlan`；`GeneralAgent` 复核计划、协调执行顺序并发出支持请求。
3. **装机** – `InstallerAgent` 按 `config.tool_install_map` 等配置检查并安装缺失工具/依赖，生成能力卡。
4. **执行** – `ExecutorHub` 将计划步骤派发给逆向、Pwn、Web、Forensics、Crypto、Misc、SymExec 等执行器代理。
5. **验证** – `ValidatorAgent` 整理执行结果，匹配 flag 模式，对证据打分并生成验证摘要。
6. **总结** – 汇总 `MissionResult`，记录回顾与后续行动建议，同时写入日志与报告文件。

## 目录结构速览

- `main.py`：CLI 入口与任务初始化逻辑。
- `framework/`：上下文、配置、控制器、日志、计划、证据、结果等基础模块。
- `agents/`：各角色代理实现，`agents/base.py` 给出统一基类。
- `agents/executors/`：专业执行器集合，如 `ReverseExecutorAgent`、`PwnExecutorAgent` 等。
- `knowledge/`：长期技能册 `skill.json` 与领域知识缓存。
- `missions/`：按 mission_id 存储 artifacts、logs、transcripts、evidence。
- `logs/`、`artifacts/`：顶层日志与原始挑战输入的默认位置。
- `scripts/`：辅助脚本，例如 `watch_events.py` 用于实时查看事件流。

## 核心模块与数据结构

- **CaseContext**（`framework/context.py`）：持有 Mission ID、输入路径、证据列表、计划历史、命令日志、Mac 终端状态等，提供统一的 `run_command`、`add_evidence`、`record_dialogue` 等接口。
- **MissionController**（`framework/controller.py`）：构建代理、载入 API 配置、管理执行器工具集，并调度各阶段。通过 `_default_toolkits` 指定执行器常用工具。
- **FrameworkConfig**（`framework/config.py`）：定义运行时配置数据类，涵盖探测命令、工具/包安装、终端控制、事件流、符号执行等；`load_config` 支持从 JSON 覆盖默认值。
- **EvidenceCard / TaskPlan / TaskStep**：位于 `framework/evidence.py` 与 `framework/plans.py`，分别描述证据、任务计划及步骤分配。
- **ValidatorLogger**（`framework/logger.py`）：集中事件记录，默认挂载 Console 与 JSONL 输出 sink，配合 `live_console` 实现实时流式展示。

## Agent 角色说明

- **DetectiveAgent**：静态侦察、地址映射生成、基础证据提炼；支持 ELF/Mach-O/压缩包等格式解析。
- **StrategistAgent**：基于证据与技能册生成结构化计划，使用 `ask_json` 强制 JSON 输出保证结构化结果。
- **GeneralAgent**：复核计划、处理支持请求、协调执行器分配；并在缺少执行器时产生告警事件。
- **InstallerAgent**：调用 Homebrew / pip 安装缺失工具，生成能力卡并写入 artifacts。
- **Executor 系列**：位于 `agents/executors/`，按任务类型执行具体命令并把 stdout/stderr 写回 `CaseContext`。
- **ValidatorAgent**：对执行结果打分、识别 flag、撰写总结与后续建议。

## 配置要点

- `config.json`：macOS 友好的默认配置，启用自动工具安装、中文 Live 输出（`live_lang: "zh"`）、`dispatch_mode: "bulk"` 等。
- `api_config.json`：列出模型配置及角色绑定，`MissionController` 在初始化时会检查必填（`framework/controller.py` 中无有效配置会抛异常）。
- 技能册 `knowledge/skill.json`：由 `SkillBook` 管理，记录常见模式与复用经验，在规划/验证阶段引用并更新 `uses` 计数。

## 日志与产物

- Mission 目录：`missions/<mission_id>/` 下包含 `artifacts/`（命令脚本与输出）、`logs/events.jsonl`（实时事件）、`evidence.json`、`transcript.txt` 等。
- 命令执行由 `CaseContext.run_command` 自动生成 shell 脚本并捕获输出；`ValidatorLogger` 记录 `command`、`evidence`、`dialogue` 等事件类型。
- `ConsoleSink` 支持 `simple`/`fancy`/`converge` 样式的实时显示，可结合 `live_maxlen`、`live_verbosity` 控制输出粒度。

## 运行与调试流程

1. **准备环境**：确认 `api_config.json` 包含有效模型与密钥；安装 Python 3.11、Homebrew 及必要的逆向工具。
2. **快速验证**：执行 `python3 main.py --dry-run --live` 检查流程是否正常触发；如需观看事件流可加 `--watch-events`。
3. **控制终端行为**：若不希望使用 AppleScript 控制 Terminal，可在配置中将 `macos_terminal_control` 设为 false。
4. **调整轮次**：根据挑战复杂度修改 `config.max_rounds` 与 `dispatch_mode`；特殊任务可启用 `enable_angr` 获取符号执行支持。
5. **复盘分析**：运行完成后查看 `missions/<mission_id>/logs/events.jsonl`、`transcript.txt` 与最终报告，对照技能册积累经验。

## 注意事项

- 框架默认在 macOS 上运行，如迁移至 Linux 需调整 Terminal 控制与工具可用性。
- 自动安装工具会修改本地环境，若需禁止请在配置中关闭 `auto_install_tools`/`auto_install_python_tools`。
- Mission 目录可能包含敏感凭据与命令输出，请按团队策略控制访问权限。
- 若 Agentscope 或模型服务异常，`BaseAgent.call_model` 会记录 `model_error` 并返回错误摘要，可在日志中排查。

