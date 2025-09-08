# bpfsnoop Rust 迁移技术决策记录

## 1. 概述
本文档记录 bpfsnoop 从 Go 迁移到 Rust 过程中的关键技术决策、选择理由和备选方案。

## 2. 核心技术选择

### 1. eBPF 库选择

#### 决策：使用 `aya` 作为主要 eBPF 库

**理由**：
- **纯 Rust 实现**：与项目目标一致，避免 C 绑定复杂性
- **类型安全**：编译时检查，减少运行时错误
- **现代化 API**：设计更符合 Rust 惯例
- **活跃维护**：Facebook/Meta 支持，社区活跃
- **异步支持**：原生支持 tokio，适合高性能场景

**备选方案**：
- `libbpf-rs`：更成熟但依赖 C 库
- `redbpf`：较老，维护不够活跃

**风险缓解**：
- 如果 aya 功能不足，准备回退到 libbpf-rs
- 抽象化 eBPF 操作，便于切换实现

### 2. C 表达式编译器设计

#### 决策：nom/Chumsky 解析器 + 复杂的自研 eBPF 代码生成器

**重要教训**：严重低估了 eBPF 代码生成的复杂度！

**现实检查**：
- **解析器**: 仅占 5% 工作量 (nom/Chumsky 可解决)
- **eBPF 代码生成**: 占 85% 工作量 (必须完全重新实现)
- **BTF 集成**: 占 10% 工作量 (类型系统集成)

**修正后的架构**：
```
Input C Expression 
    ↓
C Parser (nom/Chumsky) - 5% 工作量 ✅ 可用现成库
    ↓  
AST Processing (内部表示转换) - 10% 工作量
    ↓
Semantic Analysis (BTF 类型检查) - 10% 工作量  
    ↓
eBPF Code Generation (指令生成) - 65% 工作量 ⚠️ 最复杂
    ↓
Register Allocation (寄存器分配) - 5% 工作量
    ↓
Memory Safety (内存访问安全) - 5% 工作量
    ↓
Output eBPF Instructions
```

**解析器选择** (相对次要):
1. **nom** (推荐)
   - **优势**：成熟稳定，高性能，完全控制
   - **劣势**：学习曲线，但工作量不大

2. **Chumsky** (现代选择)
   - **优势**：现代 API，优秀错误报告
   - **劣势**：相对较新

3. **~~cexpr~~** (不推荐)
   - **问题**：几年没维护，功能受限

**支持的 C 表达式子集**：
```c
// 支持的操作符
数值比较: ==, !=, <, <=, >, >=
逻辑运算: &&, ||, !
算术运算: +, -, *, /, %
位运算: &, |, ^, <<, >>
成员访问: ->, .
数组访问: []
类型转换: (type)expr

// 支持的类型
基础类型: int, char, short, long, unsigned variants
指针类型: T*
结构体: struct T (通过 BTF)
数组: T[N]
```

### 3. 构建系统设计

#### 决策：使用 build.rs + cargo 实现 eBPF 嵌入

**构建流程**：
```rust
// build.rs 伪代码
fn main() {
    // 1. 检查构建依赖 (clang, bpftool)
    check_build_dependencies()?;
    
    // 2. 生成 vmlinux.h
    generate_vmlinux_header()?;
    
    // 3. 编译所有 eBPF C 程序
    let programs = compile_ebpf_programs()?;
    
    // 4. 提取 BTF 信息
    let btf_data = extract_btf_info(&programs)?;
    
    // 5. 生成 Rust 绑定代码
    generate_rust_bindings(&programs, &btf_data)?;
    
    // 6. 嵌入字节码到可执行文件
    embed_bytecode(&programs)?;
}
```

**关键特性**：
- **增量编译**：只重新编译修改的 eBPF 程序
- **依赖追踪**：自动检测 header 文件变化
- **多架构支持**：根据目标架构编译对应版本
- **验证集成**：编译时验证 eBPF 程序正确性

### 4. 异步架构设计

#### 决策：使用 tokio + 多任务并发模型

**架构模式**：
```rust
// 主事件循环设计
async fn run_bpfsnoop(config: Config) -> Result<()> {
    let (event_tx, event_rx) = mpsc::channel(1000);
    let (output_tx, output_rx) = mpsc::channel(1000);
    
    // 任务1: eBPF 事件读取
    let reader_task = tokio::spawn(async move {
        let mut reader = RingBufReader::new()?;
        while let Some(raw_event) = reader.next().await {
            event_tx.send(raw_event?).await?;
        }
        Ok(())
    });
    
    // 任务2: 事件解析和过滤
    let processor_task = tokio::spawn(async move {
        while let Some(raw_event) = event_rx.recv().await {
            if let Ok(event) = parse_event(raw_event) {
                if filter_event(&event) {
                    output_tx.send(event).await?;
                }
            }
        }
        Ok(())
    });
    
    // 任务3: 格式化输出
    let output_task = tokio::spawn(async move {
        while let Some(event) = output_rx.recv().await {
            println!("{}", format_event(&event)?);
        }
        Ok(())
    });
    
    // 等待所有任务完成
    try_join!(reader_task, processor_task, output_task)?;
    Ok(())
}
```

**选择理由**：
- **高吞吐量**：异步处理避免阻塞
- **资源隔离**：不同任务独立执行
- **背压控制**：通过 channel 容量控制内存使用
- **错误隔离**：单个任务失败不影响其他任务

### 5. 内存管理策略

#### 决策：零拷贝 + 对象池模式

**策略实现**：
```rust
// 事件对象池
pub struct EventPool {
    pool: Arc<Mutex<Vec<Box<Event>>>>,
}

impl EventPool {
    pub fn get(&self) -> Box<Event> {
        self.pool.lock().unwrap().pop()
            .unwrap_or_else(|| Box::new(Event::default()))
    }
    
    pub fn put(&self, mut event: Box<Event>) {
        event.reset();
        self.pool.lock().unwrap().push(event);
    }
}

// 零拷贝事件读取
pub struct ZeroCopyReader {
    buffer: Pin<Box<[u8]>>,
    events: VecDeque<Event>,
}

impl ZeroCopyReader {
    pub fn read_events(&mut self) -> impl Iterator<Item = &Event> {
        // 直接在缓冲区中解析事件，避免内存拷贝
        self.parse_buffer_in_place()
    }
}
```

**优化目标**：
- **减少分配**：重用对象，避免频繁分配释放
- **减少拷贝**：原地解析，减少数据移动
- **内存局部性**：相关数据放在一起，提高缓存命中率

### 6. 错误处理策略

#### 决策：分层错误处理 + 结构化错误信息

**错误类型设计**：
```rust
// 核心错误类型
#[derive(thiserror::Error, Debug)]
pub enum BpfsnoopError {
    #[error("eBPF program failed to load: {source}")]
    EbpfLoad { source: aya::EbpfError },
    
    #[error("Filter compilation failed: {message}")]
    FilterCompile { message: String },
    
    #[error("BTF parsing failed: {path}")]
    BtfParse { path: PathBuf },
    
    #[error("Kernel function not found: {name}")]
    KernelFunctionNotFound { name: String },
    
    #[error("Invalid configuration: {field}")]
    InvalidConfig { field: String },
}

// 结果类型别名
pub type Result<T> = std::result::Result<T, BpfsnoopError>;

// 错误上下文链
use anyhow::Context;

fn load_program() -> anyhow::Result<Program> {
    Program::load()
        .with_context(|| "Failed to load main eBPF program")
        .with_context(|| format!("Configuration: {:?}", config))
}
```

### 7. 配置管理设计

#### 决策：分层配置 + 验证器模式

**配置结构**：
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfsnoopConfig {
    // 跟踪配置
    pub tracing: TracingConfig,
    // 过滤配置  
    pub filters: FilterConfig,
    // 输出配置
    pub output: OutputConfig,
    // 性能配置
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone)]
pub struct TracingConfig {
    pub kernel_functions: Vec<String>,
    pub tracepoints: Vec<String>,
    pub max_events: Option<usize>,
    pub buffer_size: usize,
}

// 配置验证
impl BpfsnoopConfig {
    pub fn validate(&self) -> Result<()> {
        self.tracing.validate()?;
        self.filters.validate()?;
        self.output.validate()?;
        self.performance.validate()?;
        Ok(())
    }
}
```

**配置来源优先级**：
1. 命令行参数（最高优先级）
2. 环境变量
3. 配置文件
4. 默认值（最低优先级）

### 8. 测试策略

#### 决策：分层测试 + 性能回归检测

**测试金字塔**：
```
       /\
      /  \  E2E Tests (少量)
     /____\
    /      \  Integration Tests (适量)
   /________\
  /          \  Unit Tests (大量)
 /______________\
```

**具体实现**：
```rust
// 单元测试
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_expression_parsing() {
        let expr = "skb->len > 100";
        let ast = parse_expression(expr).unwrap();
        assert_eq!(ast.op, BinaryOp::Greater);
    }
    
    #[test] 
    fn test_btf_function_lookup() {
        let btf = BtfParser::from_kernel().unwrap();
        let func = btf.find_function("tcp_sendmsg").unwrap();
        assert!(!func.params.is_empty());
    }
}

// 集成测试
#[tokio::test]
async fn test_end_to_end_tracing() {
    let config = test_config();
    let tracer = Tracer::new(config).await.unwrap();
    
    // 启动跟踪
    let handle = tracer.start().await.unwrap();
    
    // 触发系统调用
    std::fs::File::open("/dev/null").unwrap();
    
    // 验证事件
    let events = handle.collect_events(Duration::from_millis(100)).await;
    assert!(!events.is_empty());
}

// 性能基准测试
#[bench]
fn bench_event_processing(b: &mut Bencher) {
    let events = generate_test_events(1000);
    b.iter(|| {
        for event in &events {
            black_box(process_event(event));
        }
    });
}
```

## 3. 性能优化策略

### 1. 编译时优化
- **内联关键函数**：频繁调用的小函数标记 `#[inline]`
- **常量折叠**：编译时计算常量表达式
- **死代码消除**：使用 feature flags 移除未使用功能

### 2. 运行时优化
- **SIMD 加速**：在合适的地方使用 SIMD 指令
- **分支预测**：使用 `likely/unlikely` 宏
- **内存预分配**：预先分配足够的缓冲区

### 3. 系统级优化
- **CPU 亲和性**：绑定关键线程到特定 CPU
- **NUMA 感知**：在多 NUMA 节点系统上优化内存分配
- **页面锁定**：锁定关键数据结构到物理内存

## 4. 部署和发布策略

### 1. 构建系统
- **多目标编译**：支持不同架构和发行版
- **静态链接**：减少运行时依赖
- **符号表剥离**：减小可执行文件大小

### 2. 包管理
- **Cargo 发布**：将核心库发布到 crates.io
- **系统包**：提供 deb/rpm 包
- **容器镜像**：提供预构建的容器镜像

### 3. 版本管理
- **语义化版本**：遵循 semver 规范
- **发布日志**：详细的变更记录
- **兼容性承诺**：API 兼容性保证

## 5. 风险评估和缓解

### 技术风险
| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| aya 功能不足 | 中 | 高 | 准备 libbpf-rs 备选方案 |
| C 编译器复杂度 | 高 | 中 | 分阶段实现，MVP 优先 |
| 性能回归 | 中 | 中 | 持续基准测试 |
| eBPF 验证器限制 | 低 | 高 | 深入研究验证器规则 |

### 项目风险
| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| 开发时间超期 | 中 | 中 | 预留缓冲时间，分阶段交付 |
| 团队技能不足 | 低 | 高 | 技术培训，专家咨询 |
| 需求变更 | 中 | 低 | 灵活的架构设计 |

## 6. 技术债务管理

### 1. 代码质量
- **定期重构**：每月进行一次代码审查和重构
- **技术债务跟踪**：使用 issue 跟踪已知的技术债务
- **文档更新**：保持文档与代码同步

### 2. 依赖管理
- **依赖审计**：定期检查依赖的安全性和更新
- **版本锁定**：在稳定版本中锁定依赖版本
- **替代方案**：为关键依赖准备替代方案

### 3. 性能监控
- **持续监控**：建立性能监控仪表板
- **回归检测**：自动检测性能回归
- **优化计划**：定期评估和实施性能优化

本技术决策文档将在项目进行过程中不断更新，确保技术选择的合理性和项目的成功交付。
