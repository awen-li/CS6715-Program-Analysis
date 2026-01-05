#ifndef ANALYSIS_H
#define ANALYSIS_H
#include <iostream>
#include "llvm/IR/Module.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "generic_graph.h"
#include "graph_visual.h"
#include "llvm_wrapper.h"

//-----------------------------------------
// base class of Analyzer
//-----------------------------------------
class Analyzer 
{
public:
    virtual ~Analyzer() = default;
    virtual void runAnalysis(LLVM& llvmParser, const std::string& filename) = 0;
};


//-----------------------------------------
// A Toy Analyzer
//-----------------------------------------
class AnalyzerToy : public Analyzer 
{
public:
    void runAnalysis(LLVM& llvmParser, const std::string& filename) override 
    {
        (void)llvmParser;
        std::cout<<"Hello CS6717, this is a toy analyzer.\n";
    }
};


//-----------------------------------------
// Analyzer Factory
//-----------------------------------------
class AnalyzerFactory 
{
public:
    AnalyzerFactory() 
    { 
        registerAnalyzers(); 
    }

    ~AnalyzerFactory() = default;

    Analyzer* getAnalyzer(const std::string& type);
private:
    void registerAnalyzers();

private:
    std::map<std::string, std::unique_ptr<Analyzer>> analyzers;
};

#endif // ANALYSIS_H
