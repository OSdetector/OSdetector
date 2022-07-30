//===---- tools/extra/ToolTemplate.cpp - Template for refactoring tool ----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file implements an empty refactoring tool using the clang tooling.
//  The goal is to lower the "barrier to entry" for writing refactoring tools.
//
//  Usage:
//  tool-template <cmake-output-dir> <file1> <file2> ...
//
//  Where <cmake-output-dir> is a CMake build directory in which a file named
//  compile_commands.json exists (enable -DCMAKE_EXPORT_COMPILE_COMMANDS in
//  CMake to get this output).
//
//  <file1> ... specify the paths of files in the CMake source tree. This path
//  is looked up in the compile command database. If the path of a file is
//  absolute, it needs to point into CMake's source tree. If the path is
//  relative, the current working directory needs to be in the CMake source
//  tree and the file must be in a subdirectory of the current working
//  directory. "./" prefixes in the relative files will be automatically
//  removed, but the rest of a relative path must be a suffix of a path in
//  the compile command line database.
//
//  For example, to use tool-template on all files in a subtree of the
//  source tree, use:
//
//    /path/in/subtree $ find . -name '*.cpp'|
//        xargs tool-template /path/to/build
//
//===----------------------------------------------------------------------===//
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Execution.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Refactoring/AtomicChange.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Signals.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace llvm;

namespace {
class ToolTemplateCallback : public MatchFinder::MatchCallback {
public:
  ToolTemplateCallback(ExecutionContext &Context, std::string type_name) : Context(Context) {
    type = type_name;
  }

  void run(const MatchFinder::MatchResult &Result) override {
    // TODO: This routine will get called for each thing that the matchers
    // find.
    // At this point, you can examine the match, and do whatever you want,
    // including replacing the matched text with other text
    // auto *D = Result.Nodes.getNodeAs<NamedDecl>("decl");
    auto *D = Result.Nodes.getNodeAs<clang::FunctionDecl>(type);
    assert(D);
    // Context.reportResult("TYPE", type);
    std::cout<<"============================================================================\n";
    std::cout<< "Tag:\n" << type << "\n\n";
    // Use AtomicChange to get a key.
    if (D->getBeginLoc().isValid()) {
      AtomicChange Change(*Result.SourceManager, D->getBeginLoc());
      // Context.reportResult(Change.getKey(), D->getQualifiedNameAsString());
      std::cout<<"Location:\n"<<Change.getKey()<<"\n"<<D->getQualifiedNameAsString()<<"\n\n";
    }
    D = Result.Nodes.getNodeAs<clang::FunctionDecl>("func_name");
    // Context.reportResult("Function name", D->getName());
    std::cout<<"Function Name:\n"<<D->getName().str()<<"\n\n";
    std::cout<<"============================================================================\n\n";
  }

private:
  ExecutionContext &Context;
  std::string type;
};
} // end anonymous namespace

// Set up the command line options
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::OptionCategory ToolTemplateCategory("tool-template options");

struct result{
    std::string type_list[10];
    std::string func_name[10][10];
    int cnt = 0;
};
struct result readFile(std::string filename)
{
  struct result res;
  std::ifstream fin;
  fin.open(filename, std::ios::in);
  if(!fin)
  {
    std::cerr << "Can not open "<< filename<<std::endl;
    exit(0);
  }
  std::string line;
  for(int i = 0; fin>>line && i<10; i++)
  {
    // line.erase(std::remove(line.begin(), line.end(), ' '), line.end()); 
    res.type_list[i] = line.substr(0, line.find(":"));
    line = line.substr(line.find(":")+1, line.length()) + ",";
    for(int j = 0; line.find(",") != std::string::npos && j < 10; j++, line=line.substr(line.find(",")+1, line.length()))
    {
      res.func_name[i][j] = line.substr(0, line.find(","));
    }
    res.cnt++;
  }
  return res;
}


int main(int argc, const char **argv) {
  llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);

  auto Executor = clang::tooling::createExecutorFromCommandLineArgs(
      argc, argv, ToolTemplateCategory);

  if (!Executor) {
    llvm::errs() << llvm::toString(Executor.takeError()) << "\n";
    return 1;
  }

  ast_matchers::MatchFinder Finder;

  struct result res = readFile("./target_func");
  for(int i = 0; i < res.cnt; i++)
  {
    ToolTemplateCallback* Callback = new ToolTemplateCallback(*Executor->get()->getExecutionContext(), res.type_list[i]); // FIXME:具有内存泄露问题
    for(std::string func_name : res.func_name[i])
    {
        if(func_name=="\0")
          break;
        Finder.addMatcher(
          functionDecl(
            hasDescendant(
              callExpr(callee(
                functionDecl(hasName(func_name)).bind("func_name"))
              )
            )
          ).bind(res.type_list[i]),
            Callback
        );
    }
  }

  auto Err = Executor->get()->execute(newFrontendActionFactory(&Finder));
  if (Err) {
    llvm::errs() << llvm::toString(std::move(Err)) << "\n";
  }
  Executor->get()->getToolResults()->forEachResult(
      [](llvm::StringRef key, llvm::StringRef value) {
        llvm::errs() << "----" << key.str() << "\n" << value.str() << "\n";
      });
}
