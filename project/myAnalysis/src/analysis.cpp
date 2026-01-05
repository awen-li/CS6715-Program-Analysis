#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/GraphWriter.h"
#include "analysis.h"


void AnalyzerFactory::registerAnalyzers() 
{
    analyzers.emplace("toy", std::make_unique<AnalyzerToy>());

    // register your analyzer here

    return;
}

Analyzer* AnalyzerFactory::getAnalyzer(const std::string& type) 
{
    auto it = analyzers.find(type);
    if (it == analyzers.end()) 
    {
        throw std::runtime_error("Unknown analyzer type: " + type);
    }
    return it->second.get();
}

