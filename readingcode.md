
<!-- TOC -->
- [1. run_qsym_afl.py main](#1-run_qsym_aflpy-main)auto    
- [1.1. parse_args() 解析命令 run_qsym.py](#11-parse_args-解析命令-run_qsympy)auto    
- [1.2. AFLExecutor 构造](#12-aflexecutor-构造)auto    - [1.3. e.run 执行](#13-erun-执行)auto        - [1.3.1. sync_files 与fuzzer同步文件](#131-sync_files-与fuzzer同步文件)auto        - [1.3.2. run_file 测试样本](#132-run_file-测试样本)auto            - [1.3.2.1. check_so_file() 检查pintool so](#1321-check_so_file-检查pintool-so)auto            - [1.3.2.2. self.run_target()  运行](#1322-selfrun_target--运行)auto            - [1.3.2.3. self.handle_by_return_code(ret, fp) 处理返回码,分类保存测试样本](#1323-selfhandle_by_return_coderet-fp-处理返回码分类保存测试样本)auto            - [1.3.2.4. q.get_testcases(): 获取测试例](#1324-qget_testcases-获取测试例)auto            - [1.3.2.5. self.minimizer.check_testcase(testcase): 检查测试例](#1325-selfminimizercheck_testcasetestcase-检查测试例)auto                - [1.3.2.5.1. self.is_interesting_testcase(this_bitmap, proc.returncode)检查是否interesting](#13251-selfis_interesting_testcasethis_bitmap-procreturncode检查是否interesting)auto            - [1.3.2.6. self.check_crashes() 同步崩溃样本序号](#1326-selfcheck_crashes-同步崩溃样本序号)auto- [2. self.run_target()  运行 1.2.2.2](#2-selfrun_target--运行-1222)auto    - [2.1. executor.Executor(self.cmd, self.cur_input, self.tmp_dir, bitmap=self.bitmap, argv=["-l", "1"]) Executor构造](#21-executorexecutorselfcmd-selfcur_input-selftmp_dir-bitmapselfbitmap-argv-l-1-executor构造)auto    - [2.2. q.run(self.state.timeout) 运行](#22-qrunselfstatetimeout-运行)auto        - [2.2.1. self.gen_cmd(timeout) pin命令行](#221-selfgen_cmdtimeout-pin命令行)auto        - [2.2.2. ExecutorResult](#222-executorresult)auto- [3. pintool main](#3-pintool-main)auto    - [3.1. checkOpt())  参数](#31-checkopt--参数)auto    - [3.2. hookSyscalls 系统调用](#32-hooksyscalls-系统调用)auto        - [3.2.1. initializeSyscallDesc(); 初始化](#321-initializesyscalldesc-初始化)auto        - [3.2.2. kFdSet.insert(STDIN_FILENO);  hook stdin](#322-kfdsetinsertstdin_fileno--hook-stdin)auto        - [3.2.3. setSocketCallHook(); hook net](#323-setsocketcallhook-hook-net)auto        - [3.2.4. setMMapHookForFile();  hook fs](#324-setmmaphookforfile--hook-fs)auto    - [3.3. initializeGlobalContext(  建立上下文](#33-initializeglobalcontext--建立上下文)auto        - [3.3.1. g_solver = new Solver(input, out_dir, bitmap);  solver类](#331-g_solver--new-solverinput-out_dir-bitmap--solver类)auto            - [3.3.1.1. checkOutDir();  检查输出目录是否合法](#3311-checkoutdir--检查输出目录是否合法)auto            - [3.3.1.2. readInput();  读入输入](#3312-readinput--读入输入)auto        - [3.3.2. g_expr_builder = SymbolicExprBuilder::create();  符号执行表达式](#332-g_expr_builder--symbolicexprbuildercreate--符号执行表达式)auto            - [3.3.2.1. create ??](#3321-create-)auto    - [3.4. initializeQsym();初始化](#34-initializeqsym初始化)auto        - [3.4.1. initializeThreadContext(); 线程初始化](#341-initializethreadcontext-线程初始化)auto            - [3.4.1.1. PIN_AddThreadStartFunction(allocateThreadContext, NULL);线程进入](#3411-pin_addthreadstartfunctionallocatethreadcontext-null线程进入)auto            - [3.4.1.2. PIN_AddThreadFiniFunction(freeThreadContext,	NULL);线程退出](#3412-pin_addthreadfinifunctionfreethreadcontext	null线程退出)auto        - [3.4.2. initializeMemory(); 内存初始化](#342-initializememory-内存初始化)auto            - [3.4.2.1. g_memory.initialize(); 内存模型](#3421-g_memoryinitialize-内存模型)auto            - [3.4.2.2. IMG_AddInstrumentFunction(loadImage, NULL);](#3422-img_addinstrumentfunctionloadimage-null)auto        - [3.4.3. PIN_AddSyscallEntryFunction(onSyscallEnter, NULL); 系统调用进入](#343-pin_addsyscallentryfunctiononsyscallenter-null-系统调用进入)auto        - [3.4.4. PIN_AddSyscallExitFunction(onSyscallExit, NULL); 系统调用退出](#344-pin_addsyscallexitfunctiononsyscallexit-null-系统调用退出)auto        - [3.4.5. TRACE_AddInstrumentFunction(analyzeTrace, NULL); 基本块插桩](#345-trace_addinstrumentfunctionanalyzetrace-null-基本块插桩)auto            - [3.4.5.1. analyzeBBL(bbl); 基本块级分析](#3451-analyzebblbbl-基本块级分析)auto                - [3.4.5.1.1. instrumentBBL 分析代码](#34511-instrumentbbl-分析代码)auto            - [3.4.5.2. analyzeInstruction(ins); 指令级分析](#3452-analyzeinstructionins-指令级分析)auto                - [3.4.5.2.1. cmp  analyzeBinary(ins, Sub, false);](#34521-cmp--analyzebinaryins-sub-false)auto                    - [3.4.5.2.1.1. instrumentBinaryRegReg](#345211-instrumentbinaryregreg)auto                    - [3.4.5.2.1.2. ExprRef expr_res = doBinary(thread_ctx, kind, op_kind, expr_dst, expr_src); 运算](#345212-exprref-expr_res--dobinarythread_ctx-kind-op_kind-expr_dst-expr_src-运算)auto                    - [3.4.5.2.1.3. thread_ctx->setExprToReg(dst, expr_res); 赋值](#345213-thread_ctx-setexprtoregdst-expr_res-赋值)auto                - [3.4.5.2.2. jz analyzeJcc(ins, JCC_Z, false);](#34522-jz-analyzejccins-jcc_z-false)auto                - [3.4.5.2.3. mov](#34523-mov)auto        - [3.4.6. PIN_AddInternalExceptionHandler(exceptionHandler, NULL); 异常处理](#346-pin_addinternalexceptionhandlerexceptionhandler-null-异常处理)auto- [4. jz指令分析 analyzeJcc(ins, JCC_Z, false);](#4-jz指令分析-analyzejccins-jcc_z-false)auto    - [4.1. instrumentJcc](#41-instrumentjcc)auto        - [4.1.1. ExprRef e = thread_ctx->computeJcc(ctx, jcc_c, inv);计算jz表达式](#411-exprref-e--thread_ctx-computejccctx-jcc_c-inv计算jz表达式)auto            - [4.1.1.1. computeFastJcc](#4111-computefastjcc)auto            - [4.1.1.2. computeSlowJcc](#4112-computeslowjcc)auto                - [4.1.1.2.1. e = computeFlag(EFLAGS_ZF); jz](#41121-e--computeflageflags_zf-jz)auto                - [4.1.1.2.2. return flag_op->computeZF(); //liu](#41122-return-flag_op-computezf-liu)auto        - [4.1.2. g_solver->addJcc(e, taken, pc);  求解](#412-g_solver-addjcce-taken-pc--求解)auto            - [4.1.2.1. is_interesting = isInterestingJcc(e, taken, pc); //liu 是感兴趣的吗？](#4121-is_interesting--isinterestingjcce-taken-pc-liu-是感兴趣的吗)auto            - [4.1.2.2. negatePath(e, taken); //liu 翻转分支点](#4122-negatepathe-taken-liu-翻转分支点)auto                - [4.1.2.2.1. addToSolver(e, !taken);//liu](#41221-addtosolvere-takenliu)auto                - [4.1.2.2.2. bool sat = checkAndSave();//liu](#41222-bool-sat--checkandsaveliu)auto                    - [4.1.2.2.2.1. if (check() == z3::sat) {//liu](#412221-if-check--z3sat-liu)auto                    - [4.1.2.2.2.2. saveValues(postfix); //liu 保存求解值](#412222-savevaluespostfix-liu-保存求解值)auto                    - [4.1.2.2.2.3. std::vector<UINT8> values = getConcreteValues();//liu solve](#412223-stdvectoruint8-values--getconcretevaluesliu-solve)auto            - [4.1.2.3. addConstraint(e, taken, is_interesting); //liu 添加约束](#4123-addconstrainte-taken-is_interesting-liu-添加约束)auto- [5. pintool调试](#5-pintool调试)auto    - [5.1. run_qsym.py脚本](#51-run_qsympy脚本)auto    - [5.2. pin命令，5.1打印出的](#52-pin命令51打印出的)auto    - [5.3. pinbin gdb](#53-pinbin-gdb)auto    - [5.4. 编译](#54-编译)auto- [6. z3 solver的例子](#6-z3-solver的例子)auto    - [6.1. github sample](#61-github-sample)auto- [7. read 污点引入](#7-read-污点引入)auto    - [7.1. g_memory.makeExpr(ctx->arg[SYSCALL_ARG1], ctx->ret);//liu 符号化](#71-g_memorymakeexprctx-argsyscall_arg1-ctx-retliu-符号化)auto        - [7.1.1. LOG_DEBUG](#711-log_debug)auto        - [7.1.2. ExprRef e = g_expr_builder->createRead(off_++); //liu 建立符号名称](#712-exprref-e--g_expr_builder-createreadoff_-liu-建立符号名称)auto        - [7.1.3. setExprToMem(addr, e);//liu 存入内存](#713-setexprtomemaddr-eliu-存入内存)auto            - [7.1.3.1. clearExprFromMem(addr);//liu 清除](#7131-clearexprfrommemaddrliu-清除)auto            - [7.1.3.2. *getExprPtrFromMem(addr) = e;//liu 赋值](#7132-getexprptrfrommemaddr--eliu-赋值)auto                - [7.1.3.2.1. ExprRef* page = getPage(addr); //liu 找到页面](#71321-exprref-page--getpageaddr-liu-找到页面)auto                - [7.1.3.2.2. return &page[addressToOffset(addr)]; //liu 找到页面里偏移](#71322-return-pageaddresstooffsetaddr-liu-找到页面里偏移)auto    - [7.2. 从求解反推](#72-从求解反推)auto        - [7.2.1. getConcreteValues](#721-getconcretevalues)auto        - [7.2.2. readInput初始化](#722-readinput初始化)auto        - [7.2.3. solver类构造函数](#723-solver类构造函数)auto        - [7.2.4. 初始化input_file](#724-初始化input_file)auto        - [7.2.5. 在pintool 的main函数中初始化](#725-在pintool-的main函数中初始化)
<!-- /TOC -->
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
## 1.1. parse_args() 解析命令 run_qsym.py
```python
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-i", dest="input_file", help="An input file", required=True)
    p.add_argument("-o", dest="output_dir", help="An output directory", required=True)
    p.add_argument("-b", dest="bitmap", help="A bitmap file")
    p.add_argument("cmd", nargs="+",
            help="Command to execute: use %s to denote a file" % utils.AT_FILE)
    return p.parse_args()
def main():
    args = parse_args()
    q = Executor(args.cmd,
            args.input_file,
            args.output_dir,
            args.bitmap)
    q.run()
class Executor(object):
    def __init__(self, cmd, input_file, output_dir,
            bitmap=None, argv=None):
        self.cmd = cmd
        self.input_file = input_file
        self.output_dir = output_dir
        self.bitmap = bitmap
        self.argv = [] if argv is None else argv

        self.testcase_dir = self.get_testcase_dir()
        self.set_opts() //liu 设置输入
def set_opts(self):
    self.cmd, self.stdin = utils.fix_at_file(self.cmd, self.input_file)//liu 设置输入
    if self.stdin is None:
        self.source_opts = ["-f", "1"]
    else:
        self.source_opts = ["-s", "1"]

AT_FILE = "@@"
def fix_at_file(cmd, testcase):
    cmd = copy.copy(cmd)
    if AT_FILE in cmd:
        idx = cmd.index(AT_FILE)
        cmd[idx] = testcase
        stdin = None
    else:
        with open(testcase, "rb") as f:
            stdin = f.read() //liu 如果没有@@则，将读样本作为stdin

    return cmd, stdin
```
## 1.2. AFLExecutor 构造
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
## 1.3. e.run 执行
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
### 1.3.1. sync_files 与fuzzer同步文件
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
### 1.3.2. run_file 测试样本
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

#### 1.3.2.1. check_so_file() 检查pintool so
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

#### 1.3.2.2. self.run_target()  运行
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

#### 1.3.2.3. self.handle_by_return_code(ret, fp) 处理返回码,分类保存测试样本
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

#### 1.3.2.4. q.get_testcases(): 获取测试例
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
#### 1.3.2.5. self.minimizer.check_testcase(testcase): 检查测试例
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

        cmd, stdin = utils.fix_at_file(cmd, testcase)//liu 若是@@替换成文件名，若无，则读出文件内容到stdin
        with open(os.devnull, "wb") as devnull:
            proc = sp.Popen(cmd, stdin=sp.PIPE, stdout=devnull, stderr=devnull)
            proc.communicate(stdin)//liu 输入为stdin

        this_bitmap = read_bitmap_file(self.temp_file)
        return self.is_interesting_testcase(this_bitmap, proc.returncode) #liu 检查是否interesting
```
##### 1.3.2.5.1. self.is_interesting_testcase(this_bitmap, proc.returncode)检查是否interesting
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
#### 1.3.2.6. self.check_crashes() 同步崩溃样本序号
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
## 2.1. executor.Executor(self.cmd, self.cur_input, self.tmp_dir, bitmap=self.bitmap, argv=["-l", "1"]) Executor构造
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

## 2.2. q.run(self.state.timeout) 运行
```python
    def run(self, timeout=None):
        cmd = self.gen_cmd(timeout) #liu 命令行
        start_time = time.time()

        l.debug("Executing %s" % ' '.join(cmd))
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(self.stdin)//liu 以stdin为输入
        end_time = time.time()
        return ExecutorResult(
                start_time,
                end_time,
                proc.returncode,
                self.read_log_file())
```

### 2.2.1. self.gen_cmd(timeout) pin命令行
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

### 2.2.2. ExecutorResult
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
## 3.1. checkOpt())  参数
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


## 3.2. hookSyscalls 系统调用
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
### 3.2.1. initializeSyscallDesc(); 初始化

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

### 3.2.2. kFdSet.insert(STDIN_FILENO);  hook stdin

```c
namespace qsym {

set<int>     kFdSet; //liu 全局变量记录污点分析的文件句柄
std::string  kInput;

extern SyscallDesc  kSyscallDesc[kSyscallMax];
extern Memory g_memory;
```

### 3.2.3. setSocketCallHook(); hook net

```c

```

### 3.2.4. setMMapHookForFile();  hook fs

```c

```

## 3.3. initializeGlobalContext(  建立上下文
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
### 3.3.1. g_solver = new Solver(input, out_dir, bitmap);  solver类
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

#### 3.3.1.1. checkOutDir();  检查输出目录是否合法
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

#### 3.3.1.2. readInput();  读入输入
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



### 3.3.2. g_expr_builder = SymbolicExprBuilder::create();  符号执行表达式
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
#### 3.3.2.1. create ??
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

## 3.4. initializeQsym();初始化

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

### 3.4.1. initializeThreadContext(); 线程初始化
```C
static inline void
initializeThreadContext() {
	if ((g_thread_context_reg = PIN_ClaimToolRegister()) == REG_INVALID())
    LOG_FATAL("register claim failed\n");

	PIN_AddThreadStartFunction(allocateThreadContext, NULL); //liu 线程进入退出回调函数
	PIN_AddThreadFiniFunction(freeThreadContext,	NULL);
}
```

#### 3.4.1.1. PIN_AddThreadStartFunction(allocateThreadContext, NULL);线程进入
```C
static inline void
allocateThreadContext(THREADID tid, CONTEXT* ctx, INT32 flags, VOID* v) {
  g_memory.allocateStack(PIN_GetContextReg(ctx, REG_STACK_PTR));
  ThreadContext* thread_ctx = new ThreadContext();
  PIN_SetContextReg(ctx, g_thread_context_reg, (ADDRINT)thread_ctx);
}
```

#### 3.4.1.2. PIN_AddThreadFiniFunction(freeThreadContext,	NULL);线程退出
```C
static inline void
freeThreadContext(THREADID tid, const CONTEXT* ctx, INT32 code, VOID* v) {
  ThreadContext* thread_ctx =
    reinterpret_cast<ThreadContext*>(PIN_GetContextReg(ctx, g_thread_context_reg));
  delete thread_ctx;
}
```

### 3.4.2. initializeMemory(); 内存初始化
```C
static inline void
initializeMemory() {
  g_memory.initialize();
	IMG_AddInstrumentFunction(loadImage, NULL);
}
```
#### 3.4.2.1. g_memory.initialize(); 内存模型
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

#### 3.4.2.2. IMG_AddInstrumentFunction(loadImage, NULL);
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

### 3.4.3. PIN_AddSyscallEntryFunction(onSyscallEnter, NULL); 系统调用进入
```C
static void
onSyscallEnter(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v) {
  ThreadContext* thread_ctx = reinterpret_cast<ThreadContext*>(
      PIN_GetContextReg(ctx, g_thread_context_reg));
  thread_ctx->onSyscallEnter(ctx, std); //liu 外包了一层，之前注册过了，见3.2.1
}
```

### 3.4.4. PIN_AddSyscallExitFunction(onSyscallExit, NULL); 系统调用退出
```C
static void
onSyscallExit(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v) {
  ThreadContext* thread_ctx = reinterpret_cast<ThreadContext*>(
      PIN_GetContextReg(ctx, g_thread_context_reg));
  thread_ctx->onSyscallExit(ctx, std);
  thread_ctx->clearExprFromReg(getAx(sizeof(ADDRINT)));
}
```

### 3.4.5. TRACE_AddInstrumentFunction(analyzeTrace, NULL); 基本块插桩
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

#### 3.4.5.1. analyzeBBL(bbl); 基本块级分析
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
##### 3.4.5.1.1. instrumentBBL 分析代码
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

#### 3.4.5.2. analyzeInstruction(ins); 指令级分析
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

##### 3.4.5.2.1. cmp  analyzeBinary(ins, Sub, false); 
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
###### 3.4.5.2.1.1. instrumentBinaryRegReg
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
###### 3.4.5.2.1.2. ExprRef expr_res = doBinary(thread_ctx, kind, op_kind, expr_dst, expr_src); 运算
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
###### 3.4.5.2.1.3. thread_ctx->setExprToReg(dst, expr_res); 赋值
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


##### 3.4.5.2.2. jz analyzeJcc(ins, JCC_Z, false);
```C
void
analyzeJcc(INS ins, JccKind jcc_kind, bool inv) {
  INS_InsertCall(ins,
      IPOINT_BEFORE,
      (AFUNPTR)instrumentJcc,
      IARG_FAST_ANALYSIS_CALL,
      IARG_CPU_CONTEXT,
      IARG_BRANCH_TAKEN,
      IARG_BRANCH_TARGET_ADDR,
      IARG_ARG(jcc_kind),
      IARG_ARG(inv),
      IARG_END);
}
```

##### 3.4.5.2.3. mov
```C

```



### 3.4.6. PIN_AddInternalExceptionHandler(exceptionHandler, NULL); 异常处理
```C
static EXCEPT_HANDLING_RESULT
exceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo,
		PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
	ADDRINT vaddr = 0x0;

	// unaligned memory accesses
	if (PIN_GetExceptionCode(pExceptInfo) ==
			EXCEPTCODE_ACCESS_MISALIGNED) {
		// clear EFLAGS.AC
		PIN_SetPhysicalContextReg(pPhysCtxt, REG_EFLAGS,
			CLEAR_EFLAGS_AC(PIN_GetPhysicalContextReg(pPhysCtxt,
					REG_EFLAGS)));

		// the exception is handled gracefully
		return EHR_HANDLED;
	}
	// memory protection
	else if (PIN_GetExceptionCode(pExceptInfo) ==
			EXCEPTCODE_ACCESS_DENIED) {

		// get the address of the memory violation
		PIN_GetFaultyAccessAddress(pExceptInfo, &vaddr);

    if (g_memory.isUnmappedAddress(vaddr)) {
      std::cerr << "invalid access -- memory protection triggered\n";
      exit(0);
    }
	}
	return EHR_UNHANDLED;
}

```
# 4. jz指令分析 analyzeJcc(ins, JCC_Z, false);
```C
void
analyzeJcc(INS ins, JccKind jcc_kind, bool inv) {
  INS_InsertCall(ins,
      IPOINT_BEFORE,
      (AFUNPTR)instrumentJcc,
      IARG_FAST_ANALYSIS_CALL,
      IARG_CPU_CONTEXT,
      IARG_BRANCH_TAKEN, //liu 是否跳转
      IARG_BRANCH_TARGET_ADDR,
      IARG_ARG(jcc_kind),
      IARG_ARG(inv),
      IARG_END);
}
```
## 4.1. instrumentJcc
```C
analyzeJcc(ins, JCC_Z, false);
void
instrumentJcc(ThreadContext* thread_ctx,
    const CONTEXT* ctx,
    bool taken, ADDRINT target,
    JccKind jcc_c, bool inv) {
  ExprRef e = thread_ctx->computeJcc(ctx, jcc_c, inv);//liu 计算jz表达式
  if (e) {
    ADDRINT pc = PIN_GetContextReg(ctx, REG_INST_PTR);
    LOG_DEBUG("Symbolic branch at " + hexstr(pc) + ": " + e->toString() + "\n");
    /*liu 
    [DEBUG] Symbolic branch at 0x000400674: LNot(Equal(0x0, 0xFFFFFF9C + (0x0 | Read(index=0x0)))) //liu 实际就是第一个字符是d
    [DEBUG] Symbolic branch at 0x7fac1e2432da: 
    LNot
        (Equal
            (0xFFF, 
                LShr(
                    Extract(index=7, bits=1, 0x1 + (Ite(Equal(0x0, Read(index=0x4)), 0xFF, 0x0))) 
                    | Extract(index=7, bits=1, Ite(Equal(0xA, Read(index=0x3)), 0xFF, 0x0)) 
                    | Extract(index=7, bits=1, Ite(Equal(0x72, Read(index=0x2)), 0xFF, 0x0)) 
                    | Extract(index=7, bits=1, Ite(Equal(0x69, Read(index=0x1)), 0xFF, 0x0)) 
                    | Extract(index=7, bits=1, Ite(Equal(0x64, Read(index=0x0)), 0xFF, 0x0)) 
                    , 0x4)))
    */
#ifdef CONFIG_TRACE
    trace_addJcc(e, ctx, taken);
#endif
    g_solver->addJcc(e, taken, pc); //liu 求解
  }
}
```

### 4.1.1. ExprRef e = thread_ctx->computeJcc(ctx, jcc_c, inv);计算jz表达式
```C
inline ExprRef computeJcc(const CONTEXT* ctx, JccKind jcc_c, bool inv) {
      return eflags_.computeJcc(ctx, jcc_c, inv);
    }

ExprRef Eflags::computeJcc(const CONTEXT* ctx, JccKind jcc_c, bool inv) {
  if (!isValid(jcc_c))
    return NULL;
  ExprRef e = computeFastJcc(ctx, jcc_c, inv);//liu 
  if (e == NULL)
    e = computeSlowJcc(ctx, jcc_c, inv); //liu
  if (e == NULL) {
    LOG_INFO("unhandled operation: jcc=" + std::to_string(jcc_c)
        + ", inv=" + std::to_string(inv) + "\n");
  }

  return e;
}
```
#### 4.1.1.1. computeFastJcc
```C
ExprRef Eflags::computeFastJcc(const CONTEXT* ctx,
    JccKind jcc_c, bool inv) {
  // check if last operation is CC_OP_SUB
  OpKind kind = op_kinds_[start_];
  FlagOperation* flag_op = operations_[kind];
  UINT32 flags = getEflagsFromOpKind(kind);
  Kind op;

  if (kind == CC_OP_SUB) {
    switch (jcc_c) {
      case JCC_B:
        op = Ult;
        break;
      case JCC_BE:
        op = Ule;
        break;
      case JCC_L:
        op = Slt;
        break;
      case JCC_LE:
        op = Sle;
        break;
      case JCC_Z:
        op = Equal;
        break;
      case JCC_S:
        goto fast_jcc_s;
      default:
        return NULL;
    }

    if (inv)
      op = negateKind(op);
    ExprRef e = g_expr_builder->createBinaryExpr(op, flag_op->expr_dst(), flag_op->expr_src());
    return e;
  }

fast_jcc_s:
    // if operation is affected on ZF and SF
    if ((flags & EFLAGS_SF)
        && jcc_c == JCC_S) {
        if (inv)
          op = Sge;
        else
          op = Slt;
    }
    else if ((flags & EFLAGS_ZF)
              && jcc_c == JCC_Z) {
        if (inv)
          op = Distinct;
        else
          op = Equal;
    }
    else {
      // default case
      return NULL;
    }

    ExprRef expr_zero = g_expr_builder->createConstant(0, flag_op->expr_result()->bits());
    return g_expr_builder->createBinaryExpr(op, flag_op->expr_result(), expr_zero);
}
```
#### 4.1.1.2. computeSlowJcc
```C
ExprRef Eflags::computeSlowJcc(const CONTEXT* ctx, JccKind jcc_c, bool inv) {
  ExprRef e = NULL;
  bool equal = false;

  switch (jcc_c) {
    case JCC_BE:
      equal = true;
    case JCC_B:
      e = computeFlag(EFLAGS_CF);
      break;
    case JCC_LE:
      equal = true;
    case JCC_L:
      e = computeFlag(EFLAGS_SF);
      e = g_expr_builder->createDistinct(e, computeFlag(EFLAGS_OF));
      break;
    case JCC_S:
      e = computeFlag(EFLAGS_SF);
      break;
    case JCC_Z:
      e = computeFlag(EFLAGS_ZF);//liu jz
    case JCC_O:
      e = computeFlag(EFLAGS_OF);
      break;
    case JCC_P:
      e = computeFlag(EFLAGS_PF);
      break;
    default:
      UNREACHABLE();
      return NULL;
  }

  if (equal)
    e = g_expr_builder->createLOr(e, computeFlag(EFLAGS_ZF));

  if (inv)
    e = g_expr_builder->createLNot(e);

  return e;
}
```
##### 4.1.1.2.1. e = computeFlag(EFLAGS_ZF); jz
```C
ExprRef Eflags::computeFlag(Eflag flag) {
  for (INT i = 0; i < CC_OP_LAST; i++) {
    UINT32 start = (start_ - i) % CC_OP_LAST;
    /* liu
    enum OpKind {
        // from QEMU
        CC_OP_ADD,
        CC_OP_SUB,
        CC_OP_LOGIC,
        CC_OP_INC,
        CC_OP_DEC,
        CC_OP_SHL,
        CC_OP_SHR,
        CC_OP_ROR,
        CC_OP_ROL,
        CC_OP_SMUL,
        CC_OP_UMUL,
        CC_OP_BT,
        CC_OP_LAST
        };
    */
    OpKind op_kind = op_kinds_[start];
    /* liu
    OpKind op_kinds_[CC_OP_LAST]; //liu EFLAGS的私有成员变量

    */
    FlagOperation *flag_op = operations_[op_kind];

    if ((flag_op->flags() & flag) != 0) {
      // the flag is generated by this operation

      switch (flag) {
        case EFLAGS_CF:
          return flag_op->computeCF();
        case EFLAGS_PF:
          return flag_op->computePF();
        case EFLAGS_ZF:
          return flag_op->computeZF(); //liu
        case EFLAGS_SF:
          return flag_op->computeSF();
        case EFLAGS_OF:
          return flag_op->computeOF();
        default:
          return NULL;
      }
    }
  }

  // we could not find the operation for the flag
  return NULL;
}
```
##### 4.1.1.2.2. return flag_op->computeZF(); //liu
```c
ExprRef FlagOperation::computeZF() {
  ExprRef zero = g_expr_builder->createConstant(0, expr_result_->bits());
  return g_expr_builder->createBinaryExpr(Equal, expr_result_, zero);
}
```
### 4.1.2. g_solver->addJcc(e, taken, pc);  求解
```C
void Solver::addJcc(ExprRef e, bool taken, ADDRINT pc) {
  // Save the last instruction pointer for debugging
  last_pc_ = pc;

  if (e->isConcrete())
    return;

  // if e == Bool(true), then ignore
  if (e->kind() == Bool) {
    assert(!(castAs<BoolExpr>(e)->value()  ^ taken));
    return;
  }

  assert(isRelational(e.get()));

  // check duplication before really solving something,
  // some can be handled by range based constraint solving
  bool is_interesting;
  if (pc == 0) {
    // If addJcc() is called by special case, then rely on last_interested_
    is_interesting = last_interested_;
  }
  else
    is_interesting = isInterestingJcc(e, taken, pc); //liu 是感兴趣的吗？

  if (is_interesting)
    negatePath(e, taken); //liu 翻转分支点
  addConstraint(e, taken, is_interesting); //liu 添加约束
}
```
#### 4.1.2.1. is_interesting = isInterestingJcc(e, taken, pc); //liu 是感兴趣的吗？
```c
bool Solver::isInterestingJcc(ExprRef rel_expr, bool taken, ADDRINT pc) {
  bool interesting = trace_.isInterestingBranch(pc, taken); //liu 
  // record for other decision
  last_interested_ = interesting;
  return interesting;
}

bool AflTraceMap::isInterestingBranch(ADDRINT pc, bool taken) {
  ADDRINT h = hashPc(pc, taken);
  ADDRINT idx = getIndex(h);
  bool new_context = isInterestingContext(h, virgin_map_[idx]);
  bool ret = true;

  virgin_map_[idx]++;

  if ((virgin_map_[idx] | trace_map_[idx]) != trace_map_[idx]) {//liu 新的状态
    ADDRINT inv_h = hashPc(pc, !taken);
    ADDRINT inv_idx = getIndex(inv_h);

    trace_map_[idx] |= virgin_map_[idx];

    // mark the inverse case, because it's already covered by current testcase
    virgin_map_[inv_idx]++;

    trace_map_[inv_idx] |= virgin_map_[inv_idx];
    commit();

    virgin_map_[inv_idx]--;
    ret = true;
  }
  else if (new_context) {
    ret = true;
    commit();
  }
  else
    ret = false;

  prev_loc_ = h;
  return ret;
}
```
#### 4.1.2.2. negatePath(e, taken); //liu 翻转分支点
```C
void Solver::negatePath(ExprRef e, bool taken) {
  reset();
  syncConstraints(e);
  addToSolver(e, !taken);//liu 
  bool sat = checkAndSave();//liu
  if (!sat) {
    reset();
    // optimistic solving
    addToSolver(e, !taken);
    checkAndSave("optimistic");
  }
}
```
##### 4.1.2.2.1. addToSolver(e, !taken);//liu 
```C
void Solver::addToSolver(ExprRef e, bool taken) {
  e->simplify();
  if (!taken)
    e = g_expr_builder->createLNot(e);//liu 翻转
  add(e->toZ3Expr());
}

ExprRef ConstantFoldingExprBuilder::createLNot(ExprRef e) {
  if (BoolExprRef be = castAs<BoolExpr>(e))
    return createBool(!be->value());
  else
    return ExprBuilder::createLNot(e);
}

```
##### 4.1.2.2.2. bool sat = checkAndSave();//liu
```C
bool Solver::checkAndSave(const std::string& postfix) {
  if (check() == z3::sat) {//liu 检查是否可解
    saveValues(postfix); //liu 保存求解值
    return true;
  }
  else {
    LOG_DEBUG("unsat\n");
    return false;
  }
}
/*
(concat (_ BitVec i) (_ BitVec j) (_ BitVec m))
  - concatenation of bitvectors of size i and j to get a new bitvector of
    size m, where m = i + j
((_ extract i j) (_ BitVec m) (_ BitVec n))
  - extraction of bits i down to j from a bitvector of size m to yield a
    new bitvector of size n, where n = i - j + 1
(bvadd (_ BitVec m) (_ BitVec m) (_ BitVec m))
      - addition modulo 2^m
  - Bitvector Constants:
    (_ bvX n) where X and n are numerals, i.e. (_ bv13 32),
    abbreviates the term #bY of sort (_ BitVec n) such that

    [[#bY]] = nat2bv[n](X) for X=0, ..., 2^n - 1.

    See the specification of the theory's semantics for a definition
    of the functions [[_]] and nat2bv.  Note that this convention implicitly
    considers the numeral X as a number written in base 10.
      

[DEBUG] Constraints: ; 
(set-info :status unknown)
(declare-fun k!00 () (_ BitVec 8))
(declare-fun k!10 () (_ BitVec 8))
(declare-fun k!20 () (_ BitVec 8))
(declare-fun k!30 () (_ BitVec 8))
(declare-fun k!40 () (_ BitVec 8))
(assert
 (let 
 ((?x80 (concat //liu ?x80为变量，值为concat的结果
 	(_ bv0 27) //liu bv0 bv114都是十进制的值，后面跟的是bit数
 	((_ extract 7 7) (bvadd (_ bv1 8) (ite (= k!40 (_ bv0 8)) (_ bv255 8) (_ bv0 8)))) 
 	(ite (= k!30 (_ bv10 8)) (_ bv1 1) (_ bv0 1)) 
 	(ite (= k!20 (_ bv114 8)) (_ bv1 1) (_ bv0 1)) 
 	(ite (= k!10 (_ bv105 8)) (_ bv1 1) (_ bv0 1)) 
 	(ite (= k!00 (_ bv100 8)) (_ bv1 1) (_ bv0 1)))))
 (or (bvsle ?x80 (_ bv4094 32)) (bvsle (_ bv4096 32) ?x80))))
(assert
 (let ((?x942 (concat (_ bv0 27) ((_ extract 7 7) (bvadd (_ bv1 8) (ite (= k!40 (_ bv0 8)) (_ bv255 8) (_ bv0 8)))) (_ bv15 4))))
(let ((?x739 (bvadd (_ bv4095 32) (bvmul (_ bv4294967295 32) ?x942))))
(let ((?x1086 (ite (= ((_ extract 30 30) ?x739) (_ bv1 1)) (_ bv30 64) (ite (= ((_ extract 31 31) ?x739) (_ bv1 1)) (_ bv31 64) (_ bv64 64)))))
(let ((?x799 (ite (= ((_ extract 28 28) ?x739) (_ bv1 1)) (_ bv28 64) (ite (= ((_ extract 29 29) ?x739) (_ bv1 1)) (_ bv29 64) ?x1086))))
(let ((?x798 (ite (= ((_ extract 26 26) ?x739) (_ bv1 1)) (_ bv26 64) (ite (= ((_ extract 27 27) ?x739) (_ bv1 1)) (_ bv27 64) ?x799))))
(let ((?x1098 (ite (= ((_ extract 24 24) ?x739) (_ bv1 1)) (_ bv24 64) (ite (= ((_ extract 25 25) ?x739) (_ bv1 1)) (_ bv25 64) ?x798))))
(let ((?x448 (ite (= ((_ extract 22 22) ?x739) (_ bv1 1)) (_ bv22 64) (ite (= ((_ extract 23 23) ?x739) (_ bv1 1)) (_ bv23 64) ?x1098))))
(let ((?x741 (ite (= ((_ extract 20 20) ?x739) (_ bv1 1)) (_ bv20 64) (ite (= ((_ extract 21 21) ?x739) (_ bv1 1)) (_ bv21 64) ?x448))))
(let ((?x962 (ite (= ((_ extract 18 18) ?x739) (_ bv1 1)) (_ bv18 64) (ite (= ((_ extract 19 19) ?x739) (_ bv1 1)) (_ bv19 64) ?x741))))
(let ((?x998 (ite (= ((_ extract 16 16) ?x739) (_ bv1 1)) (_ bv16 64) (ite (= ((_ extract 17 17) ?x739) (_ bv1 1)) (_ bv17 64) ?x962))))
(let ((?x492 (ite (= ((_ extract 14 14) ?x739) (_ bv1 1)) (_ bv14 64) (ite (= ((_ extract 15 15) ?x739) (_ bv1 1)) (_ bv15 64) ?x998))))
(let ((?x1168 (ite (= ((_ extract 12 12) ?x739) (_ bv1 1)) (_ bv12 64) (ite (= ((_ extract 13 13) ?x739) (_ bv1 1)) (_ bv13 64) ?x492))))
(let ((?x782 (ite (= ((_ extract 10 10) ?x739) (_ bv1 1)) (_ bv10 64) (ite (= ((_ extract 11 11) ?x739) (_ bv1 1)) (_ bv11 64) ?x1168))))
(let ((?x1177 (ite (= ((_ extract 8 8) ?x739) (_ bv1 1)) (_ bv8 64) (ite (= ((_ extract 9 9) ?x739) (_ bv1 1)) (_ bv9 64) ?x782))))
(let ((?x552 (ite (= ((_ extract 6 6) ?x739) (_ bv1 1)) (_ bv6 64) (ite (= ((_ extract 7 7) ?x739) (_ bv1 1)) (_ bv7 64) ?x1177))))
(let ((?x304 (ite (= ((_ extract 4 4) ?x739) (_ bv1 1)) (_ bv4 64) (ite (= ((_ extract 5 5) ?x739) (_ bv1 1)) (_ bv5 64) ?x552))))
(let ((?x1038 (ite (= ((_ extract 2 2) ?x739) (_ bv1 1)) (_ bv2 64) (ite (= ((_ extract 3 3) ?x739) (_ bv1 1)) (_ bv3 64) ?x304))))
(let ((?x80 (concat (_ bv0 27) ((_ extract 7 7) (bvadd (_ bv1 8) (ite (= k!40 (_ bv0 8)) (_ bv255 8) (_ bv0 8)))) (ite (= k!30 (_ bv10 8)) (_ bv1 1) (_ bv0 1)) (ite (= k!20 (_ bv114 8)) (_ bv1 1) (_ bv0 1)) (ite (= k!10 (_ bv105 8)) (_ bv1 1) (_ bv0 1)) (ite (= k!00 (_ bv100 8)) (_ bv1 1) (_ bv0 1)))))
(let ((?x791 (bvadd (_ bv4095 32) (bvmul (_ bv4294967295 32) ?x80))))
(let ((?x606 (ite (= ((_ extract 30 30) ?x791) (_ bv1 1)) (_ bv30 64) (ite (= ((_ extract 31 31) ?x791) (_ bv1 1)) (_ bv31 64) (_ bv64 64)))))
(let ((?x1253 (ite (= ((_ extract 28 28) ?x791) (_ bv1 1)) (_ bv28 64) (ite (= ((_ extract 29 29) ?x791) (_ bv1 1)) (_ bv29 64) ?x606))))
(let ((?x534 (ite (= ((_ extract 26 26) ?x791) (_ bv1 1)) (_ bv26 64) (ite (= ((_ extract 27 27) ?x791) (_ bv1 1)) (_ bv27 64) ?x1253))))
(let ((?x267 (ite (= ((_ extract 24 24) ?x791) (_ bv1 1)) (_ bv24 64) (ite (= ((_ extract 25 25) ?x791) (_ bv1 1)) (_ bv25 64) ?x534))))
(let ((?x811 (ite (= ((_ extract 22 22) ?x791) (_ bv1 1)) (_ bv22 64) (ite (= ((_ extract 23 23) ?x791) (_ bv1 1)) (_ bv23 64) ?x267))))
(let ((?x889 (ite (= ((_ extract 20 20) ?x791) (_ bv1 1)) (_ bv20 64) (ite (= ((_ extract 21 21) ?x791) (_ bv1 1)) (_ bv21 64) ?x811))))
(let ((?x363 (ite (= ((_ extract 18 18) ?x791) (_ bv1 1)) (_ bv18 64) (ite (= ((_ extract 19 19) ?x791) (_ bv1 1)) (_ bv19 64) ?x889))))
(let ((?x375 (ite (= ((_ extract 16 16) ?x791) (_ bv1 1)) (_ bv16 64) (ite (= ((_ extract 17 17) ?x791) (_ bv1 1)) (_ bv17 64) ?x363))))
(let ((?x1128 (ite (= ((_ extract 14 14) ?x791) (_ bv1 1)) (_ bv14 64) (ite (= ((_ extract 15 15) ?x791) (_ bv1 1)) (_ bv15 64) ?x375))))
(let ((?x1252 (ite (= ((_ extract 12 12) ?x791) (_ bv1 1)) (_ bv12 64) (ite (= ((_ extract 13 13) ?x791) (_ bv1 1)) (_ bv13 64) ?x1128))))
(let ((?x1044 (ite (= ((_ extract 10 10) ?x791) (_ bv1 1)) (_ bv10 64) (ite (= ((_ extract 11 11) ?x791) (_ bv1 1)) (_ bv11 64) ?x1252))))
(let ((?x546 (ite (= ((_ extract 8 8) ?x791) (_ bv1 1)) (_ bv8 64) (ite (= ((_ extract 9 9) ?x791) (_ bv1 1)) (_ bv9 64) ?x1044))))
(let ((?x288 (ite (= ((_ extract 6 6) ?x791) (_ bv1 1)) (_ bv6 64) (ite (= ((_ extract 7 7) ?x791) (_ bv1 1)) (_ bv7 64) ?x546))))
(let ((?x688 (ite (= ((_ extract 4 4) ?x791) (_ bv1 1)) (_ bv4 64) (ite (= ((_ extract 5 5) ?x791) (_ bv1 1)) (_ bv5 64) ?x288))))
(let ((?x359 (ite (= ((_ extract 2 2) ?x791) (_ bv1 1)) (_ bv2 64) (ite (= ((_ extract 3 3) ?x791) (_ bv1 1)) (_ bv3 64) ?x688))))
(let ((?x787 (ite (= (ite (= k!00 (_ bv100 8)) (_ bv1 1) (_ bv0 1)) (_ bv0 1)) (_ bv0 64) (ite (= ((_ extract 1 1) ?x791) (_ bv1 1)) (_ bv1 64) ?x359))))
(= ?x787 (ite (= ((_ extract 1 1) ?x739) (_ bv1 1)) (_ bv1 64) ?x1038))))))))))))))))))))))))))))))))))))))
(check-sat)


*/

```
###### 4.1.2.2.2.1. if (check() == z3::sat) {//liu 
```C
z3::check_result Solver::check() {
  uint64_t before = getTimeStamp();
  z3::check_result res;
  LOG_STAT(
      "SMT: { \"solving_time\": " + decstr(solving_time_) + ", "
      + "\"total_time\": " + decstr(before - start_time_) + " }\n");
  // LOG_DEBUG("Constraints: " + solver_.to_smt2() + "\n");//liu 可打印求解约束
  try {
    res = solver_.check();//liu z3的check
  }
  catch(z3::exception e) {
    // https://github.com/Z3Prover/z3/issues/419
    // timeout can cause exception
    res = z3::unknown;
  }
  uint64_t cur = getTimeStamp();
  uint64_t elapsed = cur - before;
  solving_time_ += elapsed;
  LOG_STAT("SMT: { \"solving_time\": " + decstr(solving_time_) + " }\n");
  return res;
}
```
###### 4.1.2.2.2.2. saveValues(postfix); //liu 保存求解值
```C
void Solver::saveValues(const std::string& postfix) {
  std::vector<UINT8> values = getConcreteValues();//liu solve

  // If no output directory is specified, then just print it out
  if (out_dir_.empty()) {
    printValues(values);
    return;
  }

  std::string fname = out_dir_+ "/" + toString6digit(num_generated_); //liu outdir
  // Add postfix to record where it is genereated
  if (!postfix.empty())
      fname = fname + "-" + postfix;
  ofstream of(fname, std::ofstream::out | std::ofstream::binary);
  LOG_INFO("New testcase: " + fname + "\n");
  if (of.fail())
    LOG_FATAL("Unable to open a file to write results\n");

      // TODO: batch write
      for (unsigned i = 0; i < values.size(); i++) {
        char val = values[i];
        of.write(&val, sizeof(val));
      }

  of.close();
  num_generated_++;
}
```
###### 4.1.2.2.2.3. std::vector<UINT8> values = getConcreteValues();//liu solve
```C
std::vector<UINT8> Solver::getConcreteValues() {
  // TODO: change from real input
  z3::model m = solver_.get_model();//liu z3 solve
  unsigned num_constants = m.num_consts();
  std::vector<UINT8> values = inputs_;
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);//liu Return the i-th constant in the given model.
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_INT_SYMBOL) {
      int value = e.get_numeral_int(); //liu Return int value of numeral
      values[name.to_int()] = (UINT8)value;
    }
  }
  return values;
}
```

#### 4.1.2.3. addConstraint(e, taken, is_interesting); //liu 添加约束
```C
void Solver::addConstraint(ExprRef e, bool taken, bool is_interesting) {
  if (auto NE = castAs<LNotExpr>(e)) {
    addConstraint(NE->expr(), !taken, is_interesting);
    return;
  }
  if (!addRangeConstraint(e, taken))
    addNormalConstraint(e, taken);
}
```


# 5. pintool调试
## 5.1. run_qsym.py脚本
```bash
python bin/run_qsym.py -i test/1.txt -o test/out/ test/mywps 
python bin/run_qsym.py -i test/1.txt -o test/mywps_position/out/ test/mywps_position/mywps_position
```

## 5.2. pin命令，5.1打印出的
```bash
third_party/pin-2.14-71313-gcc.4.4.7-linux/pin -pause_tool 20  -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/out/pin.log -i test/1.txt -s 1 -d 1 -o test/out -- test/mywps

third_party/pin-2.14-71313-gcc.4.4.7-linux/pin  -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/out/pin.log -i test/1.txt -s 1 -d 1 -o test/out -- test/mywps

third_party/pin-2.14-71313-gcc.4.4.7-linux/pin  -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/two_read/out/pin.log -i test/1.txt -s 1 -d 1 -o test/two_read/out -- test/two_read/two_read

mywps1:
third_party/pin-2.14-71313-gcc.4.4.7-linux/pin -pause_tool 20  -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/mywps1/out/pin.log -i test/1.txt -s 1 -d 1 -o test/mywps1/out -- test/mywps1/mywps1

third_party/pin-2.14-71313-gcc.4.4.7-linux/pin  -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/mywps1/out/pin.log -i test/1.txt -s 1 -d 1 -o test/mywps1/out -- test/mywps1/mywps1

mywps_position:
third_party/pin-2.14-71313-gcc.4.4.7-linux/pin  -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/mywps_position/out/pin.log -i test/1.txt -s 1 -d 1 -o test/mywps_position/out -- test/mywps_position/mywps_position

third_party/pin-2.14-71313-gcc.4.4.7-linux/pin  -pause_tool 20 -ifeellucky -t ./qsym/pintool/obj-intel64/libqsym.so -logfile test/mywps_position/out/pin.log -i test/1.txt -s 1 -d 1 -o test/mywps_position/out -- test/mywps_position/mywps_position

```

## 5.3. pinbin gdb
```bash
cd third_party/pin-2.14-71313-gcc.4.4.7-linux/intel64/bin
gdb -q pinbin
attach 
add-symbol
dir /home/long/qsym/qsym-master/qsym/pintool  #设置源码搜索目录
select-frame n #跳转到栈帧

```
## 5.4. 编译
```
python make_pintool.py
```

# 6. z3 solver的例子
## 6.1. github sample
```C
//https://github.com/Z3Prover/z3/blob/master/examples/c%2B%2B/example.cpp
/**
   Demonstration of how Z3 can be used to prove validity of
   De Morgan's Duality Law: {e not(x and y) <-> (not x) or ( not y) }
*/
void demorgan() {
    std::cout << "de-Morgan example\n";
    
    context c;

    expr x = c.bool_const("x");
    expr y = c.bool_const("y");
    expr conjecture = (!(x && y)) == (!x || !y);
    
    solver s(c);
    // adding the negation of the conjecture as a constraint.
    s.add(!conjecture);
    std::cout << s << "\n";
    std::cout << s.to_smt2() << "\n";
    switch (s.check()) {
    case unsat:   std::cout << "de-Morgan is valid\n"; break;
    case sat:     std::cout << "de-Morgan is not valid\n"; break;
    case unknown: std::cout << "unknown\n"; break;
    }
}

/**
   \brief Find a model for <tt>x >= 1 and y < x + 3</tt>.
*/
void find_model_example1() {
    std::cout << "find_model_example1\n";
    context c;
    expr x = c.int_const("x");
    expr y = c.int_const("y");
    solver s(c);

    s.add(x >= 1);
    s.add(y < x + 3);
    std::cout << s.check() << "\n";

    model m = s.get_model();
    std::cout << m << "\n";
    // traversing the model
    for (unsigned i = 0; i < m.size(); i++) {
        func_decl v = m[i];
        // this problem contains only constants
        assert(v.arity() == 0); 
        std::cout << v.name() << " = " << m.get_const_interp(v) << "\n";
    }
    // we can evaluate expressions in the model.
    std::cout << "x + y + 1 = " << m.eval(x + y + 1) << "\n";
}

/**
   \brief Prove <tt>x = y implies g(x) = g(y)</tt>, and
   disprove <tt>x = y implies g(g(x)) = g(y)</tt>.
   This function demonstrates how to create uninterpreted types and
   functions.
*/
void prove_example1() {
    std::cout << "prove_example1\n";
    
    context c;
    expr x      = c.int_const("x");
    expr y      = c.int_const("y");
    sort I      = c.int_sort();
    func_decl g = function("g", I, I);
    
    solver s(c);
    expr conjecture1 = implies(x == y, g(x) == g(y));
    std::cout << "conjecture 1\n" << conjecture1 << "\n";
    s.add(!conjecture1);
    if (s.check() == unsat) 
        std::cout << "proved" << "\n";
    else
        std::cout << "failed to prove" << "\n";

    s.reset(); // remove all assertions from solver s

    expr conjecture2 = implies(x == y, g(g(x)) == g(y));
    std::cout << "conjecture 2\n" << conjecture2 << "\n";
    s.add(!conjecture2);
    if (s.check() == unsat) {
        std::cout << "proved" << "\n";
    }
    else {
        std::cout << "failed to prove" << "\n";
        model m = s.get_model();
        std::cout << "counterexample:\n" << m << "\n";
        std::cout << "g(g(x)) = " << m.eval(g(g(x))) << "\n";
        std::cout << "g(y)    = " << m.eval(g(y)) << "\n";
    }
}



```
# 7. read 污点引入
```c
kSyscallDesc[__NR_read] = SyscallDesc{3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, postReadHook};

void
postReadHook(SyscallContext *ctx) {
  if (unlikely((long)ctx->ret <= 0))
    return;

  // taint-source
  if (kFdSet.find(ctx->arg[SYSCALL_ARG0]) != kFdSet.end())//liu 污染源句柄
    g_memory.makeExpr(ctx->arg[SYSCALL_ARG1], ctx->ret);//liu 符号化
  else
    g_memory.clearExprFromMem(ctx->arg[SYSCALL_ARG1], ctx->ret);
}
```
## 7.1. g_memory.makeExpr(ctx->arg[SYSCALL_ARG1], ctx->ret);//liu 符号化
```c
  inline void makeExpr(ADDRINT addr, INT32 size) {
    LOG_DEBUG("makeExpr: addr=" + hexstr(addr)
        + ", size=" + hexstr(size) + "\n");
    for (INT32 i = 0; i < size; i++)
      makeExpr(addr + i); //liu
  }

  inline void makeExpr(ADDRINT addr) {
    ExprRef e = g_expr_builder->createRead(off_++); //liu 建立符号名称
    setExprToMem(addr, e);//liu 存入内存
  }
```
### 7.1.1. LOG_DEBUG
```c
#define LOG_DEBUG(msg) \
  do { \
    if (isDebugMode()) \
      log("DEBUG", msg); \
  } while(0);

bool isDebugMode() {
  return g_opt_debug.Value();
}

KNOB<bool> g_opt_debug(KNOB_MODE_WRITEONCE, "pintool",
    "d", "0", "turn on debug mode");//liu pin命令选项加上-d

void log(const char* tag, const std::string &msg) {
  std::string tagged_msg = std::string("[") + tag + "] " + msg;
  std::cerr << tagged_msg;

  LOG(tagged_msg);
}

```
### 7.1.2. ExprRef e = g_expr_builder->createRead(off_++); //liu 建立符号名称
```c
ExprRef BaseExprBuilder::createRead(ADDRINT off) {
  static std::vector<ExprRef> cache;
  if (off >= cache.size()) //liu cache
    cache.resize(off + 1);

  if (cache[off] == NULL)
    cache[off] = std::make_shared<ReadExpr>(off);//liu 相当于new了一个ReadExpr类对象

  return cache[off];
}

class ReadExpr : public NonConstantExpr {
public:
  ReadExpr(UINT32 index)
    : NonConstantExpr(Read, 8), index_(index) {
    deps_ = new DepSet();//liu typedef std::set<INT32> DepSet;
    deps_->insert(index);
    isConcrete_ = false;
  }

  std::string getName() const override { //liu
    return "Read";
  }

  inline UINT32 index() const { return index_; } //liu
  static bool classOf(const Expr& e) { return e.kind() == Read; } //liu

protected:
  bool printAux(ostream& os) const override {
    os << "index=" << hexstr(index_);
    return true;
  }

  z3::expr toZ3ExprRecursively(bool verbose) override {
    z3::symbol symbol = context_.int_symbol(index_);
    z3::sort sort = context_.bv_sort(8);
    return context_.constant(symbol, sort);
  }

  void hashAux(XXH32_state_t* state) override {
    XXH32_update(state, &index_, sizeof(index_));
  }

  bool equalAux(const Expr& other) const override {
    const ReadExpr& typed_other = static_cast<const ReadExpr&>(other);
    return index_ == typed_other.index();
  }

  ExprRef evaluateImpl() override;
  UINT32 index_;
};
```
### 7.1.3. setExprToMem(addr, e);//liu 存入内存
```c
inline void setExprToMem(ADDRINT addr, ExprRef e) {
    if (e == NULL) {
      clearExprFromMem(addr);
      return;
    }
    else {
      clearExprFromMem(addr);//liu 清除
      *getExprPtrFromMem(addr) = e;//liu 赋值
    }
  }
```
#### 7.1.3.1. clearExprFromMem(addr);//liu 清除
```c

```
#### 7.1.3.2. *getExprPtrFromMem(addr) = e;//liu 赋值
```c
inline ExprRef* getExprPtrFromMem(ADDRINT addr) {
    ExprRef* page = getPage(addr); //liu 找到页面
    // NOTE: this could happen due to ASLR
    // If we have better way to find stack address,
    // then this code could be removed
    if (page == NULL)
      return zero_page_;
    return &page[addressToOffset(addr)]; //liu 找到页面里偏移
  }
```
##### 7.1.3.2.1. ExprRef* page = getPage(addr); //liu 找到页面
```c
  inline ExprRef* getPage(ADDRINT addr) {
    auto it = page_table_.find(addressToPageIndex(addr));//liu std::unordered_map<ADDRINT, ExprRef*> page_table_; memory的成员变量
    if (it == page_table_.end())
      return NULL;
    else
      return it->second;
  }
```
##### 7.1.3.2.2. return &page[addressToOffset(addr)]; //liu 找到页面里偏移
```c
inline ADDRINT addressToOffset(ADDRINT addr) {
  return addr & kPageMask;
}

```
## 7.2. 从求解反推
### 7.2.1. getConcreteValues
```c
std::vector<UINT8> Solver::getConcreteValues() {
  // TODO: change from real input
  z3::model m = solver_.get_model();
  unsigned num_constants = m.num_consts();
  std::vector<UINT8> values = inputs_; //liu 注意这里有初始值
  //std::vector<UINT8>    inputs_; 是solver类的protected变量
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_INT_SYMBOL) {
      int value = e.get_numeral_int();
      values[name.to_int()] = (UINT8)value;
      //long debug
      printf("long debug: name = %d , value = %x\n",name.to_int(),value);
    }
  }
  return values;
}
```
### 7.2.2. readInput初始化
```c
void Solver::readInput() {
  std::ifstream ifs (input_file_, std::ifstream::in | std::ifstream::binary);
  if (ifs.fail()) {
    LOG_FATAL("Cannot open an input file\n");
    exit(-1);
  }

  char ch;
  while (ifs.get(ch))
    inputs_.push_back((UINT8)ch);//liu 读如文件内容,初始化values或者_input，文件的大小决定了vector的大小。
}
```
### 7.2.3. solver类构造函数
```c
Solver::Solver(
    const std::string input_file,
    const std::string out_dir,
    const std::string bitmap)
  : input_file_(input_file)//liu 在这里初始化输入文件
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

  checkOutDir();
  readInput();//liu 在这里初始化输入
}
```
### 7.2.4. 初始化input_file
```c
void initializeGlobalContext(
    const std::string input,
    const std::string out_dir,
    const std::string bitmap) {
  g_solver = new Solver(input, out_dir, bitmap);//liu 初始化solver和input_file

  if (g_opt_linearization.Value())
    g_expr_builder = PruneExprBuilder::create();
  else
    g_expr_builder = SymbolicExprBuilder::create();
}
```
### 7.2.5. 在pintool 的main函数中初始化
```c
int main(int argc, char** argv) {
  PIN_InitSymbols();

  if (PIN_Init(argc, argv))
    goto err;

  if (!checkOpt())
    goto err;

  hookSyscalls(
        g_opt_stdin.Value() != 0,
        g_opt_fs.Value() != 0,
        g_opt_net.Value() != 0,
        g_opt_input.Value());

  initializeGlobalContext(
      g_opt_input.Value(),//liu 根据选项-i 初始化input_file
      g_opt_outdir.Value(),
      g_opt_bitmap.Value());
  initializeQsym();
  PIN_StartProgram();

err:
  PIN_ERROR(KNOB_BASE::StringKnobSummary() + "\n");
  return kExitFailure;
}
```