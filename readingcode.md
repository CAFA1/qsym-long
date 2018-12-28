<!-- TOC -->autoauto- [1. run_qsym_afl.py main](#1-run_qsym_aflpy-main)auto    - [1.1. AFLExecutor 构造](#11-aflexecutor-构造)auto    - [1.2 e.run 执行](#12-erun-执行)autoauto<!-- /TOC -->

# 1. run_qsym_afl.py main
```python
def main():
    args = parse_args()
    check_args(args)

    e = qsym.afl.AFLExecutor(args.cmd, args.output, args.afl,
            args.name, args.filename, args.mail, args.asan_bin)
    try:
        e.run()
    finally:
        e.cleanup()
```
## 1.1. AFLExecutor 构造
```python
class AFLExecutor(object):
    def __init__(self, cmd, output, afl, name, filename=None, mail=None, asan_bin=None):
        self.cmd = cmd
        self.output = output
        self.afl = afl
        self.name = name
        self.filename = ".cur_input" if filename is None else filename
        self.mail = mail
        self.set_asan_cmd(asan_bin)

        self.tmp_dir = tempfile.mkdtemp()
        cmd, afl_path, qemu_mode = self.parse_fuzzer_stats()
        self.minimizer = minimizer.TestcaseMinimizer(
            cmd, afl_path, self.output, qemu_mode)
        self.import_state()
        self.make_dirs()
        atexit.register(self.cleanup)
```
## 1.2 e.run 执行
```python
    def run(self):
        logger.debug("Temp directory=%s" % self.tmp_dir)

        while True:
            files = self.sync_files()

            if not files:
                self.handle_empty_files()
                continue

            for fp in files:
                self.run_file(fp)
                break
```
### 1.2.1 sync_files 与fuzzer同步文件
```python
    def sync_files(self):
        files = []
        for name in os.listdir(self.afl_queue):
            path = os.path.join(self.afl_queue, name)
            if os.path.isfile(path):
                files.append(path)

        files = list(set(files) - self.state.done - self.state.processed)
        return sorted(files,
                      key=functools.cmp_to_key(testcase_compare),
                      reverse=True)
```
### 1.2.2 run_file 测试样本
```python
    def run_file(self, fp):
        check_so_file() #liu 检查pintool so

        # copy the test case
        shutil.copy2(fp, self.cur_input) #liu 拷贝

        old_idx = self.state.index
        logger.debug("Run qsym: input=%s" % fp)

        q, ret = self.run_target() #liu 运行
        self.handle_by_return_code(ret, fp) #liu 处理返回码
        self.state.processed.add(fp)

        target = os.path.basename(fp)[:len("id:......")]
        num_testcase = 0
        for testcase in q.get_testcases(): #liu 获取测试例
            num_testcase += 1
            if not self.minimizer.check_testcase(testcase): #liu 检查测试例
                # Remove if it's not interesting testcases
                os.unlink(testcase)
                continue
            index = self.state.tick()
            filename = os.path.join(
                    self.my_queue,
                    "id:%06d,src:%s" % (index, target)) #liu 新测试例的名字
            shutil.move(testcase, filename)
            logger.debug("Creating: %s" % filename)

        if os.path.exists(q.log_file):
            os.unlink(q.log_file)

        logger.debug("Generate %d testcases" % num_testcase)
        logger.debug("%d testcases are new" % (self.state.index - old_idx))

        self.check_crashes() #liu 检查是否崩溃

```

#### 1.2.2.1 check_so_file() 检查pintool so
```python
def check_so_file():
    for SO_file in SO.values():
        if not os.path.exists(SO_file):
            # Maybe updating now.. please wait
            logger.debug("Cannot find pintool. Maybe updating?")
            time.sleep(3 * 60)

        if not os.path.exists(SO_file):
            FATAL("Cannot find SO file!")
```

#### 1.2.2.2 self.run_target()  运行
```python
    def run_target(self):
        # Trigger linearlize to remove complicate expressions
        q = executor.Executor(self.cmd, self.cur_input, self.tmp_dir, bitmap=self.bitmap, argv=["-l", "1"])
        ret = q.run(self.state.timeout)
        logger.debug("Total=%d s, Emulation=%d s, Solver=%d s, Return=%d"
                     % (ret.total_time,
                        ret.emulation_time,
                        ret.solving_time,
                        ret.returncode))
        return q, ret
```

#### 1.2.2.3 self.handle_by_return_code(ret, fp) 处理返回码,分类保存测试样本
```python
    def handle_by_return_code(self, res, fp):
        retcode = res.returncode
        if retcode in [124, -9]: # killed
            shutil.copy2(fp, os.path.join(self.my_hangs, os.path.basename(fp)))
            self.state.hang.add(fp)
        else:
            self.state.done.add(fp)

        # segfault or abort
        if (retcode in [128 + 11, -11, 128 + 6, -6]):
            shutil.copy2(fp, os.path.join(self.my_errors, os.path.basename(fp))) #liu my_error目录
            '''
            def my_errors(self):
                return os.path.join(self.my_dir, "errors")
            def my_dir(self):
                return os.path.join(self.output, self.name) #output/qsym
            '''
            self.report_error(fp, res.log)
```

#### 1.2.2.4 q.get_testcases(): 获取测试例
```python
    def get_testcases(self):
        for name in sorted(os.listdir(self.testcase_dir)): #liu 求解新样本目录
        '''
        self.testcase_dir = self.get_testcase_dir()
        def last_testcase_dir(self):
            return os.path.join(self.output_dir, "qsym-last")

        '''
            if name == "stat":
                continue
            if name == "pin.log":
                continue
            path = os.path.join(self.testcase_dir, name)
            yield path
```
#### 1.2.2.5 self.minimizer.check_testcase(testcase): 检查测试例
```python
    def check_testcase(self, testcase):
        cmd = [self.showmap,
               "-t",
               str(TIMEOUT),
               "-m", "256T", # for ffmpeg
               "-b" # binary mode
        ]

        if self.qemu_mode:
            cmd += ['-Q']

        cmd += ["-o",
               self.temp_file,
               "--"
        ] + self.cmd

        cmd, stdin = utils.fix_at_file(cmd, testcase)
        with open(os.devnull, "wb") as devnull:
            proc = sp.Popen(cmd, stdin=sp.PIPE, stdout=devnull, stderr=devnull)
            proc.communicate(stdin)

        this_bitmap = read_bitmap_file(self.temp_file)
        return self.is_interesting_testcase(this_bitmap, proc.returncode) #liu 检查是否interesting
```
##### 1.2.2.5.1 self.is_interesting_testcase(this_bitmap, proc.returncode)检查是否interesting
```python
    def is_interesting_testcase(self, bitmap, returncode):
        if returncode == 0:
            my_bitmap = self.bitmap #liu 全局的bitmap
            my_bitmap_file = self.bitmap_file
        else:
            my_bitmap = self.crash_bitmap
            my_bitmap_file = self.crash_bitmap_file

        # Maybe need to port in C to speed up
        interesting = False
        for i in xrange(len(bitmap)):
            old = my_bitmap[i]
            new = my_bitmap[i] | bitmap[i]
            if old != new:
                interesting = True
                my_bitmap[i] = new #liu 更新bitmap

        if interesting:
            write_bitmap_file(my_bitmap_file, my_bitmap)
        return interesting
```
#### 1.2.2.6 self.check_crashes() 同步崩溃样本序号
```python
    def check_crashes(self):
        for fuzzer in os.listdir(self.output):
            crash_dir = os.path.join(self.output, fuzzer, "crashes")
            if not os.path.exists(crash_dir):
                continue

            # initialize if it's first time to see the fuzzer
            if not fuzzer in self.state.crashes:
                self.state.crashes[fuzzer] = -1

            for name in sorted(os.listdir(crash_dir)):
                # skip readme
                if name == "README.txt":
                    continue

                # read id from the format "id:000000..."
                num = int(name[3:9])
                if num > self.state.crashes[fuzzer]:
                    self.report_crash(os.path.join(crash_dir, name))
                    self.state.crashes[fuzzer] = num
```
# 2. self.run_target()  运行 1.2.2.2
```python
    def run_target(self):
        # Trigger linearlize to remove complicate expressions
        q = executor.Executor(self.cmd, self.cur_input, self.tmp_dir, bitmap=self.bitmap, argv=["-l", "1"]) #liu Executor构造
        ret = q.run(self.state.timeout) #liu 运行
        logger.debug("Total=%d s, Emulation=%d s, Solver=%d s, Return=%d"
                     % (ret.total_time,
                        ret.emulation_time,
                        ret.solving_time,
                        ret.returncode))
        return q, ret
```
## 2.1 executor.Executor(self.cmd, self.cur_input, self.tmp_dir, bitmap=self.bitmap, argv=["-l", "1"]) Executor构造
```python
class Executor(object):
    def __init__(self, cmd, input_file, output_dir,
            bitmap=None, argv=None):
        self.cmd = cmd
        self.input_file = input_file
        self.output_dir = output_dir
        self.bitmap = bitmap
        self.argv = [] if argv is None else argv

        self.testcase_dir = self.get_testcase_dir()
        self.set_opts()
```

## 2.2 q.run(self.state.timeout) 运行
```python
    def run(self, timeout=None):
        cmd = self.gen_cmd(timeout) #liu 命令行
        start_time = time.time()

        l.debug("Executing %s" % ' '.join(cmd))
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(self.stdin)
        end_time = time.time()
        return ExecutorResult(
                start_time,
                end_time,
                proc.returncode,
                self.read_log_file())
```

### 2.2.1 self.gen_cmd(timeout) pin命令行
```python
    def gen_cmd(self, timeout):
        cmd = []
        if timeout:
            cmd += ["timeout", "-k", str(5), str(timeout)]
        cmd += [PIN]

        # Hack for 16.04
        cmd += ["-ifeellucky"]

        # Check if target is 32bit ELF
        if self.check_elf32():
            cmd += ["-t", SO["ia32"]]
        else:
            cmd += ["-t", SO["intel64"]]

        # Add log file
        cmd += ["-logfile", self.log_file]
        cmd += ["-i", self.input_file] + self.source_opts
        cmd += ["-o", self.testcase_dir]
        cmd += self.argv

        if self.bitmap:
            cmd += ["-b", self.bitmap]
        return cmd + ["--"] + self.cmd
```

### 2.2.2 ExecutorResult
```python
class ExecutorResult(object):
    def __init__(self, start_time, end_time, returncode, log):
        self.returncode = returncode
        self.total_time = end_time - start_time
        self.log = log
        self.calc_solving_time(log, end_time)
```

# 3. pintool main
```c
int main(int argc, char** argv) {
  PIN_InitSymbols();

  if (PIN_Init(argc, argv))
    goto err;

  if (!checkOpt()) //liu 参数
    goto err;

  hookSyscalls( //liu 系统调用
        g_opt_stdin.Value() != 0,
        g_opt_fs.Value() != 0,
        g_opt_net.Value() != 0,
        g_opt_input.Value());

  initializeGlobalContext( //liu 建立上下文
      g_opt_input.Value(),
      g_opt_outdir.Value(),
      g_opt_bitmap.Value());
  initializeQsym();// liu 初始化
  PIN_StartProgram();

err:
  PIN_ERROR(KNOB_BASE::StringKnobSummary() + "\n");
  return kExitFailure;
}
```
## 3.1 checkOpt())  参数
```c
bool checkOpt() {
  bool b1 = g_opt_stdin.Value() != 0;
  bool b2 = g_opt_fs.Value() != 0;
  bool b3 = g_opt_net.Value() != 0;

  if (g_opt_input.Value().empty()) { //liu 当前的输入样本.cur_input
    LOG_INFO("No input is specified\n");
    return false;
  }

  // one of them should be true
  if (!b1 && !b2 && !b3) {
    LOG_INFO("No option is specified: use stdin\n");
    g_opt_stdin.AddValue("1");
    return true;
  }

  // three of them cannot be true at the same time
  if (b1 && b2 && b3)
    goto multiple_opt;

  // if two of them are true, then false
  // else one of them are true, then true
  if (b1 ^ b2 ^ b3)
    return true;

multiple_opt:
  LOG_INFO("More than one exclusive options are specified\n");
  return false;
}
```


## 3.2 hookSyscalls 系统调用
```c
void hookSyscalls(bool hook_stdin, bool hook_fs, bool hook_net,
                  const std::string& input) {
  initializeSyscallDesc(); //liu 初始化

  // Save input to global variable for hook
  kInput = input; //liu 输入的样本文件名

  // Add stdin to the interesting descriptors set
  if (hook_stdin != 0)
    kFdSet.insert(STDIN_FILENO); //liu hook stdin

  if (hook_net)
    setSocketCallHook(); //liu hook net

  if (hook_fs) {
    setMMapHookForFile(); //liu hook fs
    setOpenHook();
  }

  setReadHook();
  setCloseHook();
  setDupHook();
}
```
### 3.2.1 initializeSyscallDesc(); 初始化

```C
void
initializeSyscallDesc() {
  kSyscallDesc[__NR_restart_syscall] = SyscallDesc{0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL};
  kSyscallDesc[__NR_exit] = SyscallDesc{1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL};
  kSyscallDesc[__NR_fork] = SyscallDesc{0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL};
  kSyscallDesc[__NR_read] = SyscallDesc{3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, postReadHook};
  kSyscallDesc[__NR_write] = SyscallDesc{3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL};
  kSyscallDesc[__NR_open] = SyscallDesc{3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL};
  kSyscallDesc[__NR_close] = SyscallDesc{1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL};
  //liu 太长了，后面还有
  /*
    typedef struct {
	size_t	nargs;
	size_t	save_args;
  size_t  retval_args;
	size_t	map_args[kMaxSyscallArgNum];
	void	(* pre)(SyscallContext*);
	void	(* post)(SyscallContext*);
    } SyscallDesc; //liu 数据结构

    typedef struct {
    int nr;
    ADDRINT arg[kMaxSyscallArgNum];
    ADDRINT ret;
    void* aux;
    } SyscallContext;
  */
```

### 3.2.2 kFdSet.insert(STDIN_FILENO);  hook stdin

```c
namespace qsym {

set<int>     kFdSet; //liu 全局变量记录污点分析的文件句柄
std::string  kInput;

extern SyscallDesc  kSyscallDesc[kSyscallMax];
extern Memory g_memory;
```

### 3.2.3 setSocketCallHook(); hook net

```c

```

### 3.2.4 setMMapHookForFile();  hook fs

```c

```

## 3.3 initializeGlobalContext(  建立上下文
```c
void initializeGlobalContext(
    const std::string input,
    const std::string out_dir,
    const std::string bitmap) {
  g_solver = new Solver(input, out_dir, bitmap); //liu solver类

  if (g_opt_linearization.Value())
    g_expr_builder = PruneExprBuilder::create();
  else
    g_expr_builder = SymbolicExprBuilder::create(); //liu 符号执行表达式
}
```
### 3.3.1 g_solver = new Solver(input, out_dir, bitmap);  solver类
```C
Solver::Solver(
    const std::string input_file,
    const std::string out_dir,
    const std::string bitmap)
  : input_file_(input_file)
  , inputs_()
  , out_dir_(out_dir)
  , context_(g_z3_context)
  , solver_(z3::solver(context_, "QF_BV"))
  , num_generated_(0)
  , trace_(bitmap)
  , last_interested_(false)
  , syncing_(false)
  , start_time_(getTimeStamp())
  , solving_time_(0)
  , last_pc_(0)
  , dep_forest_()
{
  // Set timeout for solver
  z3::params p(context_);
  p.set(":timeout", kSolverTimeout);
  solver_.set(p);

  checkOutDir(); //liu 检查输出目录
  readInput(); //liu 读入输入
}
```

#### 3.3.1.1 checkOutDir();  检查输出目录是否合法
```C
void Solver::checkOutDir() {
  // skip if there is no out_dir
  if (out_dir_.empty()) {
    LOG_INFO("Since output directory is not set, use stdout\n");
    return;
  }

  struct stat info;
  if (stat(out_dir_.c_str(), &info) != 0
      || !(info.st_mode & S_IFDIR)) {
    LOG_FATAL("No such directory\n");
    exit(-1);
  }
}
```

#### 3.3.1.2 readInput();  读入输入
```C
void Solver::readInput() {
  std::ifstream ifs (input_file_, std::ifstream::in | std::ifstream::binary); //liu 读输入文件
  if (ifs.fail()) {
    LOG_FATAL("Cannot open an input file\n");
    exit(-1);
  }

  char ch;
  while (ifs.get(ch))
    inputs_.push_back((UINT8)ch);//liu 压栈
    /* 类的保护成员变量
        protected:
        std::string           input_file_;
        std::vector<UINT8>    inputs_;
    */
}
```



### 3.3.2 g_expr_builder = SymbolicExprBuilder::create();  符号执行表达式
```C
class SymbolicExprBuilder : public ExprBuilder {
public:
  ExprRef createConcat(ExprRef l, ExprRef r) override; //liu 表达式有这些运算
  ExprRef createAdd(ExprRef l, ExprRef r) override;
  ExprRef createSub(ExprRef l, ExprRef r) override;
  ExprRef createMul(ExprRef l, ExprRef r) override;
  ExprRef createSDiv(ExprRef l, ExprRef r) override;
  ExprRef createUDiv(ExprRef l, ExprRef r) override;
  ExprRef createAnd(ExprRef l, ExprRef r) override;
  ExprRef createOr(ExprRef l, ExprRef r) override;
  ExprRef createXor(ExprRef l, ExprRef r) override;
  ExprRef createEqual(ExprRef l, ExprRef r) override;
  ExprRef createDistinct(ExprRef l, ExprRef r) override;
  ExprRef createLOr(ExprRef l, ExprRef r) override;
  ExprRef createLAnd(ExprRef l, ExprRef r) override;
  ExprRef createLNot(ExprRef e);
  ExprRef createIte(
    ExprRef expr_cond,
    ExprRef expr_true,
    ExprRef expr_false) override;
  ExprRef createExtract(ExprRef op, UINT32 index, UINT32 bits) override;

  static ExprBuilder* create(); //liu 构造

private:
  ExprRef createAdd(ConstantExprRef l, NonConstantExprRef r);
  ExprRef createAdd(NonConstantExprRef l, NonConstantExprRef r);
  ExprRef createSub(ConstantExprRef l, NonConstantExprRef r);
  ExprRef createSub(NonConstantExprRef l, NonConstantExprRef r);
  ExprRef createMul(ConstantExprRef l, NonConstantExprRef r);
  ExprRef createAnd(ConstantExprRef l, NonConstantExprRef r);
  ExprRef createAnd(NonConstantExprRef l, NonConstantExprRef r);
  ExprRef createOr(ConstantExprRef l, NonConstantExprRef r);
  ExprRef createOr(NonConstantExprRef l, NonConstantExprRef r);
  ExprRef createXor(NonConstantExprRef l, NonConstantExprRef r);
  ExprRef createSDiv(NonConstantExprRef l, ConstantExprRef r);
  ExprRef createUDiv(NonConstantExprRef l, ConstantExprRef r);

  ExprRef simplifyLNot(ExprRef);
  ExprRef simplifyExclusiveExpr(ExprRef l, ExprRef r);
  };

```
#### 3.3.2.1 create ??
```C
ExprBuilder* SymbolicExprBuilder::create() {
  ExprBuilder* base = new BaseExprBuilder();
  ExprBuilder* commu = new CommutativeExprBuilder();
  ExprBuilder* common = new CommonSimplifyExprBuilder();
  ExprBuilder* const_folding = new ConstantFoldingExprBuilder();
  ExprBuilder* symbolic = new SymbolicExprBuilder();
  ExprBuilder* cache = new CacheExprBuilder();

  // commu -> symbolic -> common -> constant folding -> base
  commu->setNext(symbolic);
  symbolic->setNext(common);
  common->setNext(const_folding);
  const_folding->setNext(cache);
  cache->setNext(base);
  return commu;
}
```

## 3.3 initializeQsym();初始化

```c
void initializeQsym() {
  initializeThreadContext();
  initializeMemory();

	PIN_AddSyscallEntryFunction(onSyscallEnter, NULL);
	PIN_AddSyscallExitFunction(onSyscallExit, NULL);
	TRACE_AddInstrumentFunction(analyzeTrace, NULL);
	PIN_AddInternalExceptionHandler(exceptionHandler, NULL);
}
```

### 3.3.1 initializeThreadContext(); 线程初始化
```C
static inline void
initializeThreadContext() {
	if ((g_thread_context_reg = PIN_ClaimToolRegister()) == REG_INVALID())
    LOG_FATAL("register claim failed\n");

	PIN_AddThreadStartFunction(allocateThreadContext, NULL); //liu 线程进入退出回调函数
	PIN_AddThreadFiniFunction(freeThreadContext,	NULL);
}
```

#### 3.3.1.1 PIN_AddThreadStartFunction(allocateThreadContext, NULL);线程进入
```C
static inline void
allocateThreadContext(THREADID tid, CONTEXT* ctx, INT32 flags, VOID* v) {
  g_memory.allocateStack(PIN_GetContextReg(ctx, REG_STACK_PTR));
  ThreadContext* thread_ctx = new ThreadContext();
  PIN_SetContextReg(ctx, g_thread_context_reg, (ADDRINT)thread_ctx);
}
```

#### 3.3.1.2 PIN_AddThreadFiniFunction(freeThreadContext,	NULL);线程退出
```C
static inline void
freeThreadContext(THREADID tid, const CONTEXT* ctx, INT32 code, VOID* v) {
  ThreadContext* thread_ctx =
    reinterpret_cast<ThreadContext*>(PIN_GetContextReg(ctx, g_thread_context_reg));
  delete thread_ctx;
}
```

### 3.3.2 initializeMemory(); 内存初始化
```C
static inline void
initializeMemory() {
  g_memory.initialize();
	IMG_AddInstrumentFunction(loadImage, NULL);
}
```
#### 3.3.2.1 g_memory.initialize(); 内存模型
```C
 void Memory::initialize()
{
  unmapped_page_ = (ExprRef*) allocPages(
      kPageSize * sizeof(ExprRef),
      PROT_NONE);
  zero_page_ = (ExprRef*) allocPages(
      kPageSize * sizeof(ExprRef),
      PROT_READ);

  setupVdso();
}
```

#### 3.3.2.2 IMG_AddInstrumentFunction(loadImage, NULL);
```C
 static void
loadImage(IMG img, VOID* v) {
  LOG_INFO("IMG: " + IMG_Name(img) + "\n");
  if (kDynLdLnkLoaded)
    return;

  g_memory.mmap(IMG_LowAddress(img), IMG_HighAddress(img)); //liu 将库模块加载到符号内存
  g_memory.initializeBrk(IMG_HighAddress(img));

	if (IMG_Name(img).compare("/lib/ld-linux.so.2") == 0 ||
			IMG_Type(img) == IMG_TYPE_STATIC)
    kDynLdLnkLoaded = true;
}
```

### 3.3.3 PIN_AddSyscallEntryFunction(onSyscallEnter, NULL); 系统调用进入
```C
static void
onSyscallEnter(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v) {
  ThreadContext* thread_ctx = reinterpret_cast<ThreadContext*>(
      PIN_GetContextReg(ctx, g_thread_context_reg));
  thread_ctx->onSyscallEnter(ctx, std); //liu 外包了一层，之前注册过了，见3.2.1
}
```

### 3.3.4 PIN_AddSyscallExitFunction(onSyscallExit, NULL); 系统调用退出
```C
static void
onSyscallExit(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v) {
  ThreadContext* thread_ctx = reinterpret_cast<ThreadContext*>(
      PIN_GetContextReg(ctx, g_thread_context_reg));
  thread_ctx->onSyscallExit(ctx, std);
  thread_ctx->clearExprFromReg(getAx(sizeof(ADDRINT)));
}
```

### 3.3.5 TRACE_AddInstrumentFunction(analyzeTrace, NULL); 基本块插桩
```C
void
analyzeTrace(TRACE trace, VOID *v)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    analyzeBBL(bbl);//liu 基本块级分析
    for (INS ins = BBL_InsHead(bbl);
        INS_Valid(ins);
        ins = INS_Next(ins)) {
      analyzeInstruction(ins); //liu 指令级分析
    }
  }
}
```

#### 3.3.5.1 analyzeBBL(bbl); 基本块级分析
```C
void
analyzeBBL(BBL bbl) {
  BBL_InsertCall(bbl,
      IPOINT_BEFORE,
      (AFUNPTR)instrumentBBL,
      IARG_CPU_CONTEXT,
      IARG_END);
}
```
##### 3.3.5.1.1 instrumentBBL 分析代码
```C
void instrumentBBL(
    ThreadContext *thread_ctx,
    const CONTEXT* ctx) {
  g_call_stack_manager.visitBasicBlock(PIN_GetContextReg(ctx, REG_INST_PTR));
}

void CallStackManager::visitBasicBlock(ADDRINT pc) {
    last_pc_ = pc; //liu 只记录最后一个基本块地址
    pending_ = true;
  }
```

#### 3.3.5.2 analyzeInstruction(ins); 指令级分析
```C
void
analyzeInstruction(INS ins) {
  // use XED to decode the instruction and extract its opcode
	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

	if (ins_indx <= XED_ICLASS_INVALID ||
				ins_indx >= XED_ICLASS_LAST) {
    LOG_WARN("unknown opcode (opcode=" + decstr(ins_indx) + ")" + "\n");
		return;
	}

  switch (ins_indx) {
  // XED_ICLASS_AAA,
  // XED_ICLASS_AAD,
  // XED_ICLASS_AAM,
  // XED_ICLASS_AAS,
  case XED_ICLASS_ADC:
    analyzeCarry(ins, Add);
    break;
  // XED_ICLASS_ADCX,
  case XED_ICLASS_ADD:
    analyzeBinary(ins, Add, true);
    break;
  //liu 很长，后面还有很多
  case XED_ICLASS_CMP:
    analyzeBinary(ins, Sub, false); //liu cmp 指令分析
    break;

  case XED_ICLASS_JZ:
    analyzeJcc(ins, JCC_Z, false); //liu jz指令分析
    break;

  case XED_ICLASS_MOV:
  case XED_ICLASS_MOVAPD:
  case XED_ICLASS_MOVAPS:
    analyzeMov(ins); //liu mov 指令分析
    break;

  
```

##### 3.3.5.2.1 cmp  analyzeBinary(ins, Sub, false); 
```C
void
analyzeBinary(INS ins, Kind kind, bool write) {
  // write as the second argument
  analyzeBinary(
      ins, write, kind, write,
      (AFUNPTR)instrumentBinaryRegReg,
      (AFUNPTR)instrumentBinaryRegImm,
      (AFUNPTR)instrumentBinaryRegMem,
      (AFUNPTR)instrumentBinaryMemReg,
      (AFUNPTR)instrumentBinaryMemImm);
}

static void
analyzeBinary(
    INS ins,
    bool write,
    UINT arg1,
    UINT arg2,
    AFUNPTR instrument_rr,
    AFUNPTR instrument_ri,
    AFUNPTR instrument_rm,
    AFUNPTR instrument_mr,
    AFUNPTR instrument_mi) {
  if (INS_OperandIsReg(ins, OP_0)) {
    REG dst = GET_REG(ins, OP_0); //liu 目的寄存器
    if (INS_OperandIsReg(ins, OP_1)) {
      assert(instrument_rr != NULL);
      REG src = GET_REG(ins, OP_1);//liu 源寄存器
      INS_InsertCall(ins,
          IPOINT_BEFORE,
          instrument_rr, //liu 寄存器传递到寄存器
          IARG_FAST_ANALYSIS_CALL,
          IARG_CPU_CONTEXT,
          IARG_REG(dst),
          IARG_REG(src),
          IARG_ARG(arg1),
          IARG_ARG(arg2),
          IARG_END);
    }
    else if (INS_OperandIsImmediate(ins, OP_1)) {
      assert(instrument_ri != NULL);
      ADDRINT imm = INS_OperandImmediate(ins, OP_1);

      INS_InsertCall(ins,
          IPOINT_BEFORE,
          instrument_ri,
          IARG_FAST_ANALYSIS_CALL,
          IARG_CPU_CONTEXT,
          IARG_REG(dst),
          IARG_IMM(imm),
          IARG_ARG(arg1),
          IARG_ARG(arg2),
          IARG_END);
    }
    else if (INS_OperandIsMemory(ins, OP_1)) {
      assert(instrument_rm != NULL);
      INS_InsertCall(ins,
          IPOINT_BEFORE,
          instrument_rm,
          IARG_FAST_ANALYSIS_CALL,
          IARG_CPU_CONTEXT,
          IARG_REG(dst),
          IARG_MEM_READ(ins),
          IARG_ARG(arg1),
          IARG_ARG(arg2),
          IARG_END);
    }
    else
      UNREACHABLE();
  }
  else if (INS_OperandIsMemory(ins, OP_0)) {
    IARG_TYPE addr_ty, size_ty;
    getMemoryType(write, addr_ty, size_ty);

    if (INS_OperandIsReg(ins, OP_1)) {
      assert(instrument_mr != NULL);
      REG src = GET_REG(ins, OP_1);
      INS_InsertCall(ins,
          IPOINT_BEFORE,
          instrument_mr,
          IARG_FAST_ANALYSIS_CALL,
          IARG_CPU_CONTEXT,
          IARG_MEM(ins, addr_ty, size_ty),
          IARG_REG(src),
          IARG_ARG(arg1),
          IARG_ARG(arg2),
          IARG_END);
    }
    else if (INS_OperandIsImmediate(ins, OP_1)) {
      assert(instrument_mi != NULL);
      ADDRINT imm = INS_OperandImmediate(ins, OP_1);

      INS_InsertCall(ins,
          IPOINT_BEFORE,
          instrument_mi,
          IARG_FAST_ANALYSIS_CALL,
          IARG_CPU_CONTEXT,
          IARG_MEM(ins, addr_ty, size_ty),
          IARG_IMM(imm),
          IARG_ARG(arg1),
          IARG_ARG(arg2),
          IARG_END);
    }
    else
      UNREACHABLE();
  }
  else
    UNREACHABLE();
}
```
###### 3.3.5.2.1.1 instrumentBinaryRegReg
```C
void PIN_FAST_ANALYSIS_CALL
instrumentBinaryRegReg(
    ThreadContext* thread_ctx,
    const CONTEXT* ctx,
    REG dst,
    REG src,
    Kind kind,
    bool write) {
  ExprRef expr_dst = NULL;
  ExprRef expr_src = NULL;
  OpKind op_kind = getOpKindBinary(kind); //liu Sub 减法

  if (!getExprFromRegReg(
        thread_ctx,
        ctx,
        dst,
        src,
        &expr_dst,
        &expr_src)) {
    thread_ctx->invalidateEflags(op_kind);
    return;
  }

  ExprRef expr_res = doBinary(thread_ctx, kind, op_kind, expr_dst, expr_src); //liu 运算求值
  if (write)
    thread_ctx->setExprToReg(dst, expr_res); //liu 如果写的话，赋值到寄存器
}
```
###### 3.3.5.2.1.2 ExprRef expr_res = doBinary(thread_ctx, kind, op_kind, expr_dst, expr_src); 运算
```C
static ExprRef
doBinary(
    ThreadContext* thread_ctx,
    Kind kind,
    OpKind op_kind,
    ExprRef expr_dst,
    ExprRef expr_src) {
  ExprRef expr_res = g_expr_builder->createBinaryExpr(kind, expr_dst, expr_src);
  thread_ctx->setEflags(op_kind, expr_res, expr_dst, expr_src); //liu 与EFLAGS有关
  return expr_res;
}
```
###### 3.3.5.2.1.3 thread_ctx->setExprToReg(dst, expr_res); 赋值
```C
inline void setExprToReg(REG r, ExprRef e) {
      setExprToReg(r, e, 0, REG_Size(r));
    }

    inline void setExprToReg(REG r, ExprRef e, INT32 off, INT32 size) {
#ifdef __x86_64__
      if (REG_is_gr32(r) && off == 0) {
        REG full_reg = REG_FullRegName(r);
        // From intel manual
        // If 32-bit opreands generate 32-bit results
        // zero-extended to a 64-bit result
        // in the destination general-purpose register.
        for (INT32 i = 4; i < 8; i++)
          clearExprFromReg(full_reg, i, 1);
      }
#endif

      ADDRINT addr = regToRegAddr(r) + off; //liu 获得寄存器地址
      switch (size) {
        case 1:
          setExprToRegAddr(addr, e);//liu 设置表达式到地址
          break;
        case 2:
        case 4:
        case 8:
        case 16:
        case 32:
          setExprToRegAddr(addr, size, e);
          break;
        default:
          LOG_FATAL("invalid size: " + std::to_string(size) + "\n");
      }
    }

    inline ADDRINT regToRegAddr(REG r) {
      REG full_reg = REG_FullRegName(r);
      INT32 addr = map_reg_to_addr_[full_reg]; //liu 寄存器地址
      //liu INT32 map_reg_to_addr_[REG_LAST + 1];
      if (addr == -1)
        LOG_FATAL("invalid register: " + REG_StringShort(r) + "\n");
      if (REG_is_Upper8(r))
        addr += 1;
      return addr;
    }

    void initializeMapRegToAddr() {
      INT32 max_reg_addr = getMaxRegAddr();
      memset(map_reg_to_addr_, -1, sizeof(map_reg_to_addr_));
      reg_exprs_ = (ExprRef*)safeCalloc(1, sizeof(ExprRef) * max_reg_addr);
      map_addr_to_reg_ = (REG*)safeCalloc(1, sizeof(REG) * max_reg_addr);

      INT32 idx = 0;
      for (INT32 r = REG_GR_BASE; r < REG_LAST; r++) {
        REG reg = (REG)r;
        if (isInterestingReg(reg)) {
          map_reg_to_addr_[reg] = idx; //liu 寄存器地址初始化
          map_addr_to_reg_[idx] = reg;
          idx += REG_Size(reg);
        }
      }
    }

    inline void setExprToRegAddr(ADDRINT addr, ExprRef e) {
      if (e == NULL)
        clearExprFromRegAddr(addr);
      else {
        clearExprFromRegAddr(addr);
        *getExprPtrFromRegAddr(addr) = e; //liu 设置地址的值为表达式
      }
    }

```


##### 3.3.5.2.2 jz
```C

```

##### 3.3.5.2.3 mov
```C

```



### 3.3.6 PIN_AddInternalExceptionHandler(exceptionHandler, NULL); 异常处理
```C

```




