# bpfsnoop Rust 实现计划

## 1. 技术栈选择

### 核心依赖库
- **eBPF 库**: `aya` (推荐) 或 `libbpf-rs`
  - aya: 纯 Rust 实现，类型安全，API 现代化
  - libbpf-rs: libbpf 的 Rust 绑定，功能完整，与 C 版本兼容性好
- **CLI 框架**: `clap` v4 (强类型，性能好)
- **异步运行时**: `tokio` (事件循环和并发处理)
- **序列化**: `serde` + `bincode` (高性能二进制序列化)
- **日志**: `tracing` + `tracing-subscriber` (结构化日志)
- **错误处理**: `anyhow` + `thiserror` (错误处理和传播)

### 系统依赖
- **libpcap**: 通过 `pcap-sys` 或 `pcap` crate 绑定
- **capstone**: 通过 `capstone-sys` 绑定反汇编引擎
- **libbpf**: 可选，如果使用 libbpf-rs

## 2. 项目结构设计

```
bpfsnoop-rust/
├── Cargo.toml                    # 工作空间配置
├── build.rs                      # 全局构建脚本
├── bpf/                          # eBPF C 源码 (复用现有)
│   ├── bpfsnoop.c
│   ├── bpfsnoop_*.h
│   └── headers/
├── crates/
│   ├── bpfsnoop-core/           # 核心数据结构和共享代码
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── types.rs         # 核心数据类型
│   │   │   ├── config.rs        # 配置管理
│   │   │   └── error.rs         # 错误定义
│   │   └── Cargo.toml
│   ├── bpfsnoop-btf/           # BTF 解析和内核函数发现
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── parser.rs        # BTF 解析器
│   │   │   ├── kernel.rs        # 内核函数发现
│   │   │   └── symbols.rs       # 符号表处理
│   │   └── Cargo.toml
│   ├── bpfsnoop-cc/            # C 表达式编译器
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── lexer.rs         # 词法分析
│   │   │   ├── parser.rs        # 语法分析
│   │   │   ├── codegen.rs       # 代码生成
│   │   │   └── ebpf.rs          # eBPF 指令生成
│   │   └── Cargo.toml
│   ├── bpfsnoop-pcap/          # 网络包过滤
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── filter.rs        # pcap 过滤器
│   │   │   └── injection.rs     # 代码注入
│   │   └── Cargo.toml
│   ├── bpfsnoop-ebpf/          # eBPF 程序管理
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── loader.rs        # 程序加载器
│   │   │   ├── embed.rs         # 嵌入式字节码
│   │   │   └── attach.rs        # 程序附加
│   │   ├── build.rs             # eBPF 编译脚本
│   │   └── Cargo.toml
│   └── bpfsnoop-cli/           # 命令行界面
│       ├── src/
│       │   ├── main.rs
│       │   ├── args.rs          # 参数解析
│       │   ├── output.rs        # 输出格式化
│       │   └── runner.rs        # 主执行逻辑
│       └── Cargo.toml
├── tests/                       # 集成测试
│   ├── integration/
│   └── performance/
├── docs/                        # 文档
│   ├── api/
│   └── user/
└── README.md
```

## 3. 详细实现计划

### 第一阶段：基础架构 (3-4周)

#### 1.1 项目搭建 (1周)
**任务**：
- [ ] 创建 Cargo 工作空间
- [ ] 设置各 crate 的基础结构
- [ ] 配置 CI/CD 流水线
- [ ] 设置代码质量检查 (clippy, rustfmt)

**关键文件**：
```toml
# Cargo.toml
[workspace]
members = [
    "crates/bpfsnoop-core",
    "crates/bpfsnoop-btf", 
    "crates/bpfsnoop-cc",
    "crates/bpfsnoop-pcap",
    "crates/bpfsnoop-ebpf",
    "crates/bpfsnoop-cli"
]

[workspace.dependencies]
aya = { version = "0.12", features = ["async_tokio"] }
clap = { version = "4.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
```

#### 1.2 eBPF 嵌入系统 (2周)
**任务**：
- [ ] 创建 build.rs 脚本自动编译 eBPF 程序
- [ ] 实现字节码嵌入机制
- [ ] 生成 Rust 绑定代码
- [ ] 支持多架构编译

**核心代码结构**：
```rust
// bpfsnoop-ebpf/src/embed.rs
pub struct EmbeddedProgram {
    pub name: &'static str,
    pub bytecode: &'static [u8],
    pub btf_data: &'static [u8],
}

// 宏生成的代码
include!(concat!(env!("OUT_DIR"), "/bpf_programs.rs"));

// bpfsnoop-ebpf/build.rs
fn main() {
    // 编译所有 eBPF C 源文件
    // 生成字节码嵌入代码
    // 提取 BTF 信息
}
```

#### 1.3 基础 BTF 解析 (1周)
**任务**：
- [ ] 实现 BTF 数据解析
- [ ] 内核符号表读取 (/proc/kallsyms)
- [ ] 基础的类型信息提取

**核心接口**：
```rust
// bpfsnoop-btf/src/lib.rs
pub struct BtfParser {
    spec: btf::Spec,
}

impl BtfParser {
    pub fn from_kernel() -> Result<Self>;
    pub fn find_function(&self, name: &str) -> Option<&btf::Func>;
    pub fn get_func_params(&self, func: &btf::Func) -> Vec<btf::FuncParam>;
}

pub struct SymbolTable {
    symbols: HashMap<String, u64>,
}
```

### 第二阶段：核心功能 (4-5周)

#### 2.1 内核函数发现 (1.5周)
**任务**：
- [ ] 实现模式匹配算法 (glob/regex)
- [ ] 函数可跟踪性检查
- [ ] 参数数量限制检测
- [ ] 支持 tracepoint 发现

**核心功能**：
```rust
// bpfsnoop-btf/src/kernel.rs
pub struct KernelFunctionFinder {
    btf: BtfParser,
    symbols: SymbolTable,
}

impl KernelFunctionFinder {
    pub fn find_functions(&self, patterns: &[String]) -> Vec<KernelFunction>;
    pub fn check_traceable(&self, func: &KernelFunction) -> bool;
    pub fn detect_max_args(&self) -> usize;
}
```

#### 2.2 eBPF 程序管理 (1.5周)
**任务**：
- [ ] 程序加载和验证
- [ ] fentry/fexit 附加
- [ ] 映射管理 (ringbuf, 配置映射等)
- [ ] 错误处理和资源清理

**核心接口**：
```rust
// bpfsnoop-ebpf/src/loader.rs
pub struct ProgramLoader {
    programs: HashMap<String, Program>,
    maps: HashMap<String, Map>,
}

impl ProgramLoader {
    pub fn load_embedded(&mut self, prog: &EmbeddedProgram) -> Result<()>;
    pub fn attach_fentry(&mut self, target: &str) -> Result<Link>;
    pub fn attach_fexit(&mut self, target: &str) -> Result<Link>;
}
```

#### 2.3 基础过滤器 (1周)
**任务**：
- [ ] 简单表达式解析 (数值比较)
- [ ] 基础代码生成
- [ ] 字节码注入机制

**MVP 实现**：
```rust
// bpfsnoop-cc/src/lib.rs
pub struct SimpleFilter {
    expr: String,
}

impl SimpleFilter {
    pub fn compile(&self) -> Result<Vec<Instruction>>;
    pub fn inject_into(&self, program: &mut Program) -> Result<()>;
}

// 支持简单表达式: "arg0 > 100", "arg1 == 0" 等
```

#### 2.4 事件输出系统 (1周)
**任务**：
- [ ] ringbuf 事件读取
- [ ] 基础事件解析
- [ ] 简单的输出格式化
- [ ] 异步事件处理

**核心组件**：
```rust
// bpfsnoop-cli/src/output.rs
pub struct EventProcessor {
    reader: AsyncReader,
    formatter: EventFormatter,
}

impl EventProcessor {
    pub async fn process_events(&mut self) -> Result<()>;
}

pub struct EventFormatter {
    btf: BtfParser,
}

impl EventFormatter {
    pub fn format_function_call(&self, event: &FunctionEvent) -> String;
}
```

### 第三阶段：高级功能 (4-5周)

#### 3.1 C 表达式编译器 (4-5周) ⚠️ **重新评估！**
**现实检查**：严重低估了复杂度！eBPF 代码生成器才是最复杂的部分。

**重新分解的任务**：
- [ ] **解析器集成** (3-5天): nom 或 Chumsky
- [ ] **AST 设计** (1周): 内部表示和类型系统
- [ ] **BTF 集成** (1.5周): 类型检查、字段偏移、内存布局
- [ ] **eBPF 代码生成器** (2.5-3周): 🔥 **最复杂的部分**
  - 表达式求值器 (处理所有 C 操作符)
  - 寄存器分配和管理
  - 内存访问模式 (probe_read/core_read/direct_read)
  - 指令序列生成和优化
  - 验证器兼容性保证

**真实的架构复杂度**：
```rust
// bpfsnoop-cc/src/lib.rs
pub struct CCompiler {
    parser: Box<dyn CParser>,           // 5% 工作量 - 简单
    ast_processor: AstProcessor,        // 10% 工作量
    type_checker: BtfTypeChecker,       // 10% 工作量  
    codegen: EbpfCodeGenerator,         // 65% 工作量 - 最复杂！
    register_allocator: RegisterAllocator, // 5% 工作量
    optimizer: InstructionOptimizer,    // 5% 工作量
}

// 最复杂的部分 - eBPF 代码生成器
pub struct EbpfCodeGenerator {
    // 需要实现 Go 版本 eval.go 中 1400+ 行的逻辑
    instruction_builder: InstructionBuilder,
    memory_access_generator: MemoryAccessGenerator,
    expression_evaluator: ExpressionEvaluator,
    btf_layout_calculator: BtfLayoutCalculator,
}

// 需要处理的复杂表达式类型
impl ExpressionEvaluator {
    fn eval_binary_op(&mut self, op: BinOp, left: Value, right: Value) -> Result<Value>;
    fn eval_memory_access(&mut self, ptr: Value, field: &str) -> Result<Value>;
    fn eval_array_index(&mut self, array: Value, index: Value) -> Result<Value>;
    fn eval_function_call(&mut self, func: &str, args: &[Value]) -> Result<Value>;
    fn eval_cast(&mut self, target_type: BtfType, value: Value) -> Result<Value>;
    // ... 还有很多复杂操作
}
```

#### 3.2 libpcap 集成 (1周)
**任务**：
- [ ] pcap 过滤器解析
- [ ] 与现有 elibpcap 库集成
- [ ] 支持不同包类型的过滤
- [ ] 动态注入到 eBPF 程序

**集成接口**：
```rust
// bpfsnoop-pcap/src/lib.rs
pub struct PcapFilter {
    expression: String,
}

impl PcapFilter {
    pub fn new(expr: &str) -> Result<Self>;
    pub fn inject_skb_filter(&self, program: &mut Program) -> Result<()>;
    pub fn inject_xdp_filter(&self, program: &mut Program) -> Result<()>;
}
```

#### 3.3 动态字节码修改 (1.5周)
**任务**：
- [ ] eBPF 指令操作 API
- [ ] 符号解析和重定位
- [ ] 代码注入点管理
- [ ] 验证器兼容性确保

**字节码操作**：
```rust
// bpfsnoop-ebpf/src/modify.rs
pub struct BytecodeModifier {
    instructions: Vec<Instruction>,
}

impl BytecodeModifier {
    pub fn find_injection_point(&self, stub: &str) -> Option<usize>;
    pub fn inject_instructions(&mut self, pos: usize, insns: &[Instruction]);
    pub fn resolve_symbols(&mut self) -> Result<()>;
}
```

### 第四阶段：完善优化 (2-3周)

#### 4.1 性能优化 (1周)
**任务**：
- [ ] 性能基准测试建立
- [ ] 热点代码优化
- [ ] 内存使用优化
- [ ] 并发性能调优

**基准测试**：
```rust
// tests/performance/mod.rs
#[bench]
fn bench_event_processing() {
    // 测试事件处理性能
}

#[bench] 
fn bench_filter_compilation() {
    // 测试过滤器编译性能
}
```

#### 4.2 测试完善 (1周)
**任务**：
- [ ] 单元测试覆盖所有模块
- [ ] 集成测试覆盖主要场景
- [ ] 错误处理测试
- [ ] 边界条件测试

**测试策略**：
```rust
// 各 crate 的单元测试
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_btf_parsing() { }
    
    #[test]
    fn test_expression_compilation() { }
    
    #[tokio::test]
    async fn test_event_processing() { }
}

// tests/integration/ 集成测试
#[tokio::test]
async fn test_full_tracing_workflow() {
    // 端到端测试
}
```

#### 4.3 兼容性保证 (0.5周)
**任务**：
- [ ] CLI 参数完全对等
- [ ] 输出格式精确匹配
- [ ] 错误信息兼容

## 4. 关键技术细节

### eBPF 程序嵌入机制
```rust
// build.rs 生成的代码示例
pub const BPFSNOOP_PROGRAM: EmbeddedProgram = EmbeddedProgram {
    name: "bpfsnoop",
    bytecode: include_bytes!(concat!(env!("OUT_DIR"), "/bpfsnoop.o")),
    btf_data: include_bytes!(concat!(env!("OUT_DIR"), "/bpfsnoop.btf")),
};
```

### 过滤器代码注入
```rust
// 注入点定义
const FILTER_STUB: &str = "filter_arg";

// 注入实现
impl ProgramModifier {
    pub fn inject_filter(&mut self, filter_code: &[Instruction]) -> Result<()> {
        let pos = self.find_symbol(FILTER_STUB)?;
        self.replace_instructions(pos, filter_code);
        Ok(())
    }
}
```

### 异步事件处理
```rust
// 主事件循环
pub async fn run_tracer(config: Config) -> Result<()> {
    let mut event_stream = EventStream::new().await?;
    let formatter = EventFormatter::new(config.btf_info);
    
    while let Some(event) = event_stream.next().await {
        let formatted = formatter.format(&event?)?;
        println!("{}", formatted);
    }
    
    Ok(())
}
```

## 5. 风险缓解策略

### 技术风险
1. **C 编译器复杂度**：分阶段实现，先支持简单表达式
2. **eBPF 生态差异**：准备多个库的备选方案
3. **性能回归**：持续基准测试和性能监控

### 开发风险
1. **时间估算偏差**：预留 20% 缓冲时间
2. **依赖库问题**：选择稳定成熟的依赖
3. **兼容性问题**：建立完整的回归测试

## 6. 交付检查清单

### 功能完整性
- [ ] 所有 CLI 参数都已实现
- [ ] 所有过滤功能都已实现  
- [ ] 所有输出格式都已实现
- [ ] 性能达到预期标准

### 代码质量
- [ ] 所有 clippy 检查通过
- [ ] 代码覆盖率 > 80%
- [ ] 所有公共 API 有文档
- [ ] 性能回归测试通过

### 文档完整性
- [ ] README 更新
- [ ] API 文档完整
- [ ] 用户指南完整
- [ ] 迁移指南完整

此实现计划为 bpfsnoop Rust 迁移提供了详细的技术路线图和实施指导，确保项目能够按计划高质量交付。
