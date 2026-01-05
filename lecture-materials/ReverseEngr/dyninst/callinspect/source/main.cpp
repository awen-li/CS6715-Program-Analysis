#include <BPatch.h>
#include <BPatch_process.h>
#include <BPatch_image.h>
#include <BPatch_function.h>
#include <BPatch_point.h>
#include <BPatch_snippet.h>
#include <iostream>
#include <vector>

using namespace std;

bool isPrintable(const std::string& name) 
{
    for (char c : name) 
    {
        if (!isprint(static_cast<unsigned char>(c))) 
        {
            return false;
        }
    }
    return !name.empty();
}


BPatch_function* getPrintFuncion (BPatch_image* appImage)
{
    std::vector<BPatch_function*> printfFuncs;
    appImage->findFunction("printf", printfFuncs, true);
    BPatch_function* printfFunc = printfFuncs.empty() ? nullptr : printfFuncs.front();
    if (!printfFunc) 
    {
        cerr << "Failed to locate printf function" << endl;
        return NULL;
    }

    return printfFunc;
}


void instrumentFunctions (BPatch_process* app)
{
    BPatch_image* appImage = app->getImage();
    
    BPatch_function* printfFunc = getPrintFuncion (appImage);
    if (printfFunc == NULL)
    {
        return;
    }

    std::vector<BPatch_module*> modules;
    appImage->getModules(modules);

    for (auto module : modules) 
    {
        char buffer[256];
        char* moduleName = module->getName(buffer, sizeof (buffer)-1);
        if (module->isSharedLib()) {
            continue;  // Skip shared library modules
        }

        cout << "Instrumenting module: " << moduleName << endl;

        std::vector<BPatch_function*> functions;
        module->getProcedures(functions);
        for (auto func : functions) 
        {          
            vector<BPatch_point*>* entryPoints = func->findPoint(BPatch_entry);
            if (entryPoints == nullptr || entryPoints->empty()) continue;
            
            std::string funcName = func->getName();
            if (!isPrintable (funcName))
            {
                continue;
            }

            char printfFormat[256];
            snprintf(printfFormat, sizeof(printfFormat), "Function called: %s\n", funcName.c_str());
            BPatch_constExpr formatExpr(printfFormat);
            BPatch_Vector<BPatch_snippet*> printfArgs;
            printfArgs.push_back(&formatExpr);

            BPatch_funcCallExpr printfCall(*printfFunc, printfArgs);
            for (auto point : *entryPoints) 
            {
                app->insertSnippet(printfCall, *point);
                //cout << "Inserted trace for function: " << funcName << endl;
            }
        }
    }

    return;
}


int main(int argc, char** argv) 
{
    if (argc < 2) 
    {
        cerr << "Usage: " << argv[0] << " <executable>" << endl;
        return EXIT_FAILURE;
    }

    const char* executable = argv[1];

    BPatch bpatch;
    BPatch_process* app = bpatch.processCreate(executable, (const char**)&argv[1]);
    if (!app) 
    {
        cerr << "Failed to create process" << endl;
        return EXIT_FAILURE;
    }
   
    instrumentFunctions (app);

    app->continueExecution();


    while (!app->isTerminated()) 
    {
        bpatch.waitForStatusChange();
    }

    return EXIT_SUCCESS;
}
