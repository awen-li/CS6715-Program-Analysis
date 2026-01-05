#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace 
{
    struct CountBlock : public FunctionPass 
    {
        static char ID;
        CountBlock() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override 
        {
            unsigned int basicBlockCount = 0;
            for (auto &BB : F) 
            {
                basicBlockCount++;
            }
            errs() << "Function " << F.getName() << " has " 
                    << basicBlockCount << " basic blocks.\n";
            return false;
        }

        void getAnalysisUsage(AnalysisUsage &AU) const override 
        {
            AU.setPreservesAll();
        }
  };
}

char CountBlock::ID = 0;

// Register the pass with LLVM so it can be invoked with the opt tool
static RegisterPass<CountBlock> X("countBB", "Count Basic Blocks Pass",
                                   false /* Only looks at CFG */,
                                   false /* Not an analysis pass */);
