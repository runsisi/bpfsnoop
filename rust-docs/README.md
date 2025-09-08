# bpfsnoop Rust 迁移文档

本文件夹包含 bpfsnoop 从 Go 迁移到 Rust 的完整文档和技术规划。

## 1. 📋 文档列表

### 📋 核心规划文档
- **[rust-migration-overview.md](./rust-migration-overview.md)** - 📖 项目总览和快速开始指南
- **[rust-migration-requirements.md](./rust-migration-requirements.md)** - 📋 详细需求规格书
- **[rust-implementation-plan.md](./rust-implementation-plan.md)** - 🛠️ 技术实施计划
- **[technical-decisions.md](./technical-decisions.md)** - 🎯 技术决策记录

### 🔍 专项分析文档
- **[c-parser-comparison.md](./c-parser-comparison.md)** - 🔬 Rust C 解析库详细对比分析
- **[complexity-reality-check.md](./complexity-reality-check.md)** - ⚠️ 项目复杂度现实检查

## 2. 🎯 阅读顺序建议

### 📚 快速了解 (5-10分钟)
1. **[rust-migration-overview.md](./rust-migration-overview.md)** - 获得项目全貌
2. **[complexity-reality-check.md](./complexity-reality-check.md)** - 了解真实挑战

### 📖 深入理解 (30-60分钟)
3. **[rust-migration-requirements.md](./rust-migration-requirements.md)** - 理解详细需求
4. **[rust-implementation-plan.md](./rust-implementation-plan.md)** - 学习实施计划
5. **[technical-decisions.md](./technical-decisions.md)** - 理解技术选择

### 🔬 技术细节 (额外阅读)
6. **[c-parser-comparison.md](./c-parser-comparison.md)** - 解析器技术细节

## 3. 📊 项目状态概要

| 指标 | 数值 | 状态 |
|------|------|------|
| **预计开发时间** | 16-18 周 | ⚠️ 现实调整后 |
| **主要技术风险** | eBPF 代码生成器 | 🔴 高风险 |
| **文档完成度** | 100% | ✅ 已完成 |
| **技术选型** | 基本确定 | ✅ 已完成 |

## 4. 🔥 关键发现

### ⚠️ 最重要的认知转变
- **eBPF 代码生成器占 85% 工作量**，而非 C 解析器
- **需要重新实现 1400+ 行复杂的表达式求值逻辑**
- **三种内存访问模式、寄存器分配等都是技术难点**

### 🎯 技术选择确认
- **eBPF 库**: `aya` (主选择) + `libbpf-rs` (备选)
- **C 解析器**: `nom` (推荐) 或 `Chumsky`
- **CLI 框架**: `clap` v4
- **异步运行时**: `tokio`

## 5. 🚀 下一步行动

### 🏃‍♂️ 立即可开始
1. **搭建 Rust 项目结构** - 第一阶段开始
2. **实现 eBPF 程序嵌入系统** - 类似 bpf2go
3. **基础 BTF 解析功能** - 内核函数发现

### 📋 TODO 状态
当前有 18 个 TODO 项，其中 3 个已完成，15 个待完成。主要集中在四个开发阶段的具体实施任务上。

## 6. 📞 文档维护

- **创建时间**: 2024年9月
- **最后更新**: 文档创建后的现实检查修正
- **维护者**: 需要随项目进展持续更新
- **版本控制**: 所有重要变更都已记录在各文档中

---

**🎯 这套文档为 bpfsnoop Rust 迁移提供了完整的技术路线图和实施指导，经过现实检查修正，确保计划的可行性和准确性。**
