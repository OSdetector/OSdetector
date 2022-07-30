# cmake_minimum_required(VERSION 3.13.4)
# include("/home/li/llvm-project/clang/cmake/modules/AddClang.cmake")
project(StaticAnalyzer)
set(LLVM_LINK_COMPONENTS
  FrontendOpenMP
  Support
  )

add_clang_executable(static-analyzer
  StaticAnalyzer.cpp
  )

clang_target_link_libraries(static-analyzer
  PRIVATE
  clangAST
  clangASTMatchers
  clangBasic
  clangFrontend
  clangTooling
  clangToolingRefactoring
  )
