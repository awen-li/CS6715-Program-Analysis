#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace 
{

struct FunctionLoggerPass : public PassInfoMixin<FunctionLoggerPass> 
{
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) 
    {
        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();
        llvm::errs() << "Instrumenting function: " << F.getName() << "\n";

        // Declare or get reference to the logger function
        FunctionCallee logFunc = M->getOrInsertFunction(
            "printFunc",
            FunctionType::get(Type::getVoidTy(Ctx), Type::getInt8PtrTy(Ctx), false));

        IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
        Value *funcName = Builder.CreateGlobalStringPtr(F.getName());
        Builder.CreateCall(logFunc, funcName);

        return PreservedAnalyses::none();
    }
};

}

// Register pass with the new PassManager plugin interface
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() 
{
    return 
    {
        LLVM_PLUGIN_API_VERSION, "PrintFuncPass", "v0.1",
        [](PassBuilder &PB) 
        {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) 
                {
                    if (Name == "pfpass") 
                    {
                        FunctionPassManager FPM;
                        FPM.addPass(FunctionLoggerPass());

                        // Wrap function pass manager in a module adaptor
                        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                        return true;
                    }
                    return false;
                });
        }
    };
}

