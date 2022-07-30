# 代码静态检查工具

基于clang libtooling编写的代码静态检查工具，可在代码中检查相关敏感函数的出现情况，定位到调用了该敏感函数的函数所在位置与函数名，便于使用probe与trace进行追踪。

## 1 安装说明

首先获取llvm，[官方说明](https://clang.llvm.org/get_started.html)。

然后将本文件夹移动至 `/path/to/llvm-project/clang-tool-extra/`目录下，并在 `/path/to/llvm-project/clang-tool-extra/CMakeLists.txt`中添加 `add_subdirectory(static-analyzer)。`

然后进入`/path/to/llvm-project/build` 目录重新执行 `cmake ../llvm `，使用 `make `或 `ninja `编译 `static-analyzer`，即可在`/path/to/llvm-project/build/bin/`目录下找到`static-analyzer`.

## 2 使用说明
进入代码工程目录后，首先使用CMake或其他工具生成`compile_commands.json`，然后在当前目录下新建`target_func`文件，用于指示工具寻找哪些函数，内容格式如下：
```
Tag1:func1,func2,func3
Tag2:func4
```
其中Tag数量不超过10个，每个Tag中函数不超过10个，本文件夹下的target_func已给出部分脆弱函数，可参考使用。

确定`target_func`文件后，通过如下命令对代码进行分析:
`/path/to/llvm-project/build/bin/static-analyzer -p . <file1> <file2> ...`

输出如下样例所示：
```
============================================================================
Tag:
file

Location:
/home/li/repository/bcc_detector/OSdetector/snoop/new/low_cpu_test/search_example.c:119
generate_file

Function Name:
fopen
============================================================================
```
其中`Tag`即为`target_func`中的`Tag`，`Location`为调用了这一类函数的函数所在的位置与函数名，`Function Name`为具体的脆弱函数。
