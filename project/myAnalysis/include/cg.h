
#ifndef _CG_H_
#define _CG_H_
#include <algorithm>
#include <iostream>
#include <vector>
#include <queue>
#include <unordered_set>
#include "generic_graph.h"
#include "graph_visual.h"

using namespace std;

class CGNode;  // Forward declaration
class CGEdge : public GenericEdge<CGNode> 
{
public:
    CGEdge(CGNode* s, CGNode* d)
        : GenericEdge<CGNode>(s, d) {}
    
    ~CGEdge() {}
};

class CGNode : public GenericNode<CGEdge> 
{  
public:
    typedef vector<llvm::CallBase*>::iterator cs_iterator;

    CGNode(unsigned Id, llvm::Function* func = NULL)
        : GenericNode<CGEdge>(Id) { llvmFunc = func; }

    ~CGNode() {}

    llvm::Function* getLLVMFunc ()
    {
        return llvmFunc;
    }

    void addCallsite (llvm::CallBase* callInst)
    {
        callsites.push_back (callInst);
    }

    cs_iterator begin () { return callsites.begin (); }
    cs_iterator end () { return callsites.end (); }

private:
    llvm::Function* llvmFunc;
    vector<llvm::CallBase*> callsites;
};

class CG : public GenericGraph<CGNode, CGEdge> 
{
public:
    CG(LLVM *llvmpas = NULL) { llvmParser = llvmpas; }
    ~CG() {}

public:
    
    /*
    * ============================
    * CG::build() — Pseudocode
    * ============================
    *
    * Goal:
    *   Build the Call Graph (CG) from the LLVM module loaded by llvmParser.
    *   The CG contains:
    *     - One CGNode per function (skip declarations).
    *     - One CGEdge from caller -> callee for each direct call instruction.
    *   Also record callsites and collect indirect-call sites for later handling.
    *
    * ------------------------------------------------------------
    * Step 0: Safety check
    *   If llvmParser is null, nothing to build.
    *
    * ------------------------------------------------------------
    * Step 1: Create CG nodes (one node per function)
    *   For each Function F in the module:
    *     - Skip if F is a declaration (no body).
    *     - Create a CGNode for F: node = addCGNode(F)
    *     - Save mapping: func2Nodes[F] = node
    *
    * Why do we need func2Nodes?
    *   Later, when we see a call instruction that targets callee function G,
    *   we can quickly find G’s CGNode using this map.
    *
    * ------------------------------------------------------------
    * Step 2: Create CG edges (traverse functions and find call instructions)
    *   Maintain:
    *     visited  : set of CGNodes already processed
    *     worklist : queue for BFS-style traversal over CGNodes
    *
    *   For each CGNode startNode in the graph:
    *     - If already visited, skip.
    *     - Push startNode into worklist.
    *
    *     While worklist is not empty:
    *       (A) Pop one caller node from worklist.
    *           Mark it visited.
    *           callerFunc = callerNode.getLLVMFunc()
    *
    *       (B) Scan all instructions inside callerFunc:
    *           for each BasicBlock BB in callerFunc:
    *             for each Instruction I in BB:
    *
    *             (B1) Skip debug instructions:
    *                  if I is DbgInfoIntrinsic or DbgVariableIntrinsic:
    *                      continue
    *
    *             (B2) Check if I is a call-like instruction:
    *                  callInst = dyn_cast<CallBase>(&I)
    *                  if callInst is null:
    *                      continue
    *
    *             (B3) Direct call case:
    *                  calleeFunc = callInst->getCalledFunction()
    *                  if calleeFunc != null:
    *                      calleeNode = getCGNode(calleeFunc)
    *                      addCGEdge(callerNode, calleeNode)
    *
    *                      // BFS expansion: process callee later if not visited
    *                      if calleeNode not in visited:
    *                          push calleeNode into worklist
    *
    *             (B4) Indirect call case (function pointer):
    *                  else (calleeFunc == null):
    *                      fpVal = callInst->getCalledOperand()
    *                      fpVal = fpVal->stripPointerCasts()
    *                      value2IndirectCS[fpVal].insert(callInst)
    *
    *                  // Note: We cannot add a CG edge yet because the target
    *                  // function is not directly known at this point.
    *
    *             (B5) Record the callsite in the caller node:
    *                  callerNode->addCallsite(callInst)
    *
    * ------------------------------------------------------------
    * Output of this build:
    *   - All functions with bodies become nodes in CG.
    *   - For each *direct* call instruction, add an edge caller -> callee.
    *   - All callsites are stored in their caller nodes (node->addCallsite).
    *   - Indirect callsites are collected into value2IndirectCS for later resolution.
    *
    * Common mistakes to avoid:
    *   - Forgetting to skip declarations (will cause missing bodies / null iteration).
    *   - Forgetting to record func2Nodes mapping (callee lookup will fail).
    *   - Adding duplicate edges without checks (depends on addCGEdge implementation).
    */
    void build()
    {
        // implementation here
    }

    inline CGNode* getCGNode (llvm::Function *llvmFunc)
    {
        auto itr = func2Nodes.find(llvmFunc);
        if (itr == func2Nodes.end())
        {
            return NULL;
        }
        return itr->second;
    }

    static set<llvm::CallBase*> getCallsites (llvm::Value* fVal)
    {
        auto it = value2IndirectCS.find(fVal);
        if (it == value2IndirectCS.end())
        {
            return {};
        }

        return it->second;
    }

private:
    inline unsigned getNextNodeId () 
    {
        return getNodeNum() + 1;
    }

    inline CGNode* addCGNode (llvm::Function *llvmFunc) 
    {
        CGNode *node = new CGNode(getNextNodeId(), llvmFunc);
        assert (node != NULL);
        addNode(node->getId(), node);

        return node;
    }

    inline CGEdge* addCGEdge (CGNode *src, CGNode *dst) 
    {
        CGEdge *edge = new CGEdge(src, dst);
        assert (edge != NULL);
        addEdge(edge); 

        return edge;
    }
private:
    LLVM *llvmParser;
    map<llvm::Function*, CGNode*> func2Nodes;
    static map<llvm::Value*, set<llvm::CallBase*>> value2IndirectCS;
};

class CGVisual : public GraphVis<CGNode, CGEdge, CG>
{
public:
    CGVisual(std::string graphName, CG* graph)
        : GraphVis<CGNode, CGEdge, CG>(graphName, graph) {}
    
    ~CGVisual() {}

    inline string getNodeAttributes(CGNode *node) 
    {
        string str = "shape=rectangle, color=black";   
        return str;
    }

    inline string getNodeLabel(CGNode *node) 
    {
        llvm::Function *F = node->getLLVMFunc ();

        string str = "";
        str = F->getName ().str();
        return str;
    }
};

#endif 
