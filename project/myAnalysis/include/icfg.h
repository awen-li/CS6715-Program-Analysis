#ifndef _ICFG_H_
#define _ICFG_H_
#include "cfg.h"
#include "cg.h"

class ICFG : public GenericGraph<CFGNode, CFGEdge> 
{
public:
    typedef map<llvm::Function*, CFG*>::iterator cfg_iteratoir;

    ICFG(LLVM *llvmpas = NULL) { llvmParser = llvmpas; }
    ~ICFG() 
    {
        delete cg;
        for (auto itr = cfg_begin (); itr != cfg_end (); itr++)
        {
            delete itr->second;
        }
    }
    
    void build() 
    {
        buildCFGs();

        cg = new CG (llvmParser);
        assert(cg != NULL);
        cg->build();

        buildICFG(cg);
        return;
    }

    cfg_iteratoir cfg_begin () { return func2CFG.begin (); }
    cfg_iteratoir cfg_end () { return func2CFG.end (); }
    LLVM* getLLVMParser () { return llvmParser; }
    CG* getCG () { return cg; }
    inline CFG* getCFG (llvm::Function* F)
    {
        auto it = func2CFG.find (F);
        if (it == func2CFG.end ())
        {
            return NULL;
        }
        return it->second;
    }
    
private:
    void buildCFGs()
    {
        if (!llvmParser) return;

        unsigned nodeId = 1;
        for (auto it = llvmParser->func_begin(); it != llvmParser->func_end(); ++it) 
        {
            llvm::Function* F = *it;
            if (F->isDeclaration()) continue;

            CFG *cfg = new CFG(nodeId);
            assert (cfg != NULL);
            cfg->build(*F);
            
            func2CFG [F] = cfg;
            nodeId += cfg->getNodeNum ();
        }

        return;
    }

    /*
    * ==========================================
    * ICFG::buildICFG(cg) — Pseudocode Annotation
    * ==========================================
    *
    * Goal:
    *   Build the Interprocedural Control Flow Graph (ICFG) by connecting
    *   per-function CFGs using call graph (CG) edges.
    *
    * What we add to the ICFG:
    *   For each call from caller -> callee, we add two interprocedural edges:
    *
    *     (1) Call edge:   callSite  --->  calleeCFG.entry
    *     (2) Return edge: calleeCFG.exit ---> retSite
    *
    * Important:
    *   - callSite is the CFG node where the call happens in the caller.
    *   - retSite is the CFG node where execution continues after the call returns.
    *   - One caller->callee relation may have multiple (callSite, retSite) pairs.
    *     Example: the caller function may call the same callee at multiple callsites.
    *
    * Inputs:
    *   cg : Call Graph that contains nodes (functions) and edges (calls)
    *
    * Helper functions used (provided by the template):
    *   - getCFG(Function* F) -> CFG*:
    *       returns the CFG previously built for F (or null if not available)
    *   - getCallRetSitesNodes(callerCFG, callerCGNode, calleeFunc)
    *       -> vector of (callSiteNode, retSiteNode) pairs
    *       finds all callsites inside callerFunc that target calleeFunc, and
    *       returns where to jump back after the call.
    *
    * Pseudocode:
    *   For each caller function in the CG:
    *     1) Fetch callerCFG. If missing, skip.
    *     2) For each outgoing CG edge caller -> callee:
    *          a) Fetch calleeCFG. If missing, skip.
    *          b) Find all call/return-site pairs in caller that invoke this callee:
    *               pairs = getCallRetSitesNodes(callerCFG, callerCGNode, calleeFunc)
    *          c) Let calleeEntry = calleeCFG.entryNode
    *             Let calleeExit  = calleeCFG.exitNode
    *          d) For each (callSite, retSite) in pairs:
    *               add ICFG edge: callSite  -> calleeEntry
    *               add ICFG edge: calleeExit -> retSite
    *
    * Notes / Pitfalls:
    *   - Do NOT connect calleeExit back to callSite; it must go to retSite.
    *   - If calleeFunc is external (no CFG), you skip adding call/return edges.
    *     (The callerCFG still represents local flow; the template chooses to skip.)
    *   - There can be multiple callsites to the same callee; handle all of them.
    */
    void buildICFG(CG *cg)
    {
        // implementation here
    }


private:
    LLVM *llvmParser;
    CG *cg;
    map<llvm::Function*, CFG*> func2CFG;

private:
    // get all callsiete / return-site nodes in callerCFG for calleeFunc
    // first: callsite node; 
    // second: retsite node
    inline vector<pair<CFGNode*, CFGNode*>> getCallRetSitesNodes(CFG* callerCFG, 
                                                                 CGNode* cgNode, 
                                                                 llvm::Function* calleeFunc) 
    {
        vector<pair<CFGNode*, CFGNode*>> csRsNodes;
        for (auto itCs = cgNode->begin (); itCs != cgNode->end (); itCs++) 
        {
            llvm::CallBase* callInst = *itCs;
            llvm::Function* callee = callInst->getCalledFunction();
            if (callee != calleeFunc)
            {
                continue;
            }

            // get callsite node in callerCFG
            CFGNode* cfgNode = callerCFG->getCFGNode (callInst);
            assert (cfgNode != NULL);

            // get return-site node in callerCFG
            CFGNode* retNode = nullptr;
            for (auto itEdge = cfgNode->outEdgeBegin (); itEdge != cfgNode->outEdgeEnd (); itEdge++)
            {
                CFGEdge* edge = *itEdge;
                CFGNode* succNode = edge->getDstNode ();
                retNode = succNode;
                break;
            }
            assert(retNode != NULL);

            csRsNodes.push_back (make_pair(cfgNode, retNode));
        }

        return csRsNodes;
    }
};

class ICFGVisual : public GraphVis<CFGNode, CFGEdge, ICFG>
{
public:
    ICFGVisual(std::string graphName, ICFG* graph)
        : GraphVis<CFGNode, CFGEdge, ICFG>(graphName, graph) {}
    
    ~ICFGVisual() {}

    inline string getNodeLabel (CFGNode *node)
    {
        if (node->isEntry ())
        {
            CFGEntryNode* enNode = (CFGEntryNode*)node;
            llvm::Function* func = enNode->getFunction ();
            return LLVM().getValueLabel (func);
        }
        else if (node->isExit ())
        {
            return "exit";
        }
        else
        {
            llvm::Instruction* inst = node->getInstruction ();
            std::string instStr = LLVM().getValueLabel (inst);;
            return escapeForDotLabel (instStr);
        }
    }

    inline string getEdgeAttributes(CFGEdge *edge) 
    {
        if (edge->edgeType & EDGE_ICFG)
        {
            return "color=red";
        }
        else
        {
            return "color=black";
        }
    }

    inline void writeCFGNodes (CFG *cfg)
    {
        for (auto it = cfg->begin (), end = cfg->end (); it != end; it++)
        {
            CFGNode *node = it->second;
            if (!IsVizNode (node))
            {
                continue;
            }
            writeNodes (node);
        }
    }

    inline void writeCFGAllEdges (CFG *cfg)
    {
        for (auto it = cfg->begin (), end = cfg->end (); it != end; it++)
        {
            CFGNode *node = it->second;
            if (!IsVizNode (node))
            {
                continue;
            }

            for (auto itEdge = node->outEdgeBegin (), itEnd = node->outEdgeEnd (); itEdge != itEnd; itEdge++)
            {
                CFGEdge *edge = *itEdge;
                if (!IsVizNode (edge->getDstNode()))
                {
                    continue;
                }
                
                writeEdge (edge);
            }
        }
    }

    void writeGraph () 
    {
        writeHeader(m_GraphName);

        // write nodes
        fprintf(m_File, "\t// Define the nodes\n");
        for (auto it = m_Graph->cfg_begin (), end = m_Graph->cfg_end (); it != end; it++)
        {
            CFG *cfg = it->second;
            writeCFGNodes (cfg);
        }
        //writeAllNodes (m_Graph);
        fprintf(m_File, "\n\n");

        // write edges
        fprintf(m_File, "\t// Define the edges\n");
        for (auto it = m_Graph->cfg_begin (), end = m_Graph->cfg_end (); it != end; it++)
        {
            CFG *cfg = it->second;
            writeCFGAllEdges (cfg);
        }
        //writeAllEdges (m_Graph);
        fprintf(m_File, "}\n");
    }

    inline string getNodeAttributes(CFGNode *node) 
    {
        string str = "shape=rectangle, color=black";   
        return str;
    }  
};

#endif