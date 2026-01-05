#include <BPatch.h>
#include <BPatch_binaryEdit.h>
#include <BPatch_image.h>
#include <BPatch_function.h>
#include <BPatch_module.h>
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

BPatch_function* getPrintFunction(BPatch_image* appImage) 
{
    std::vector<BPatch_function*> printfFuncs;
    appImage->findFunction("printf", printfFuncs, true);
    BPatch_function* printfFunc = printfFuncs.empty() ? nullptr : printfFuncs.front();
    if (!printfFunc) 
    {
        cerr << "Failed to locate printf function" << endl;
        return nullptr;
    }
    return printfFunc;
}

void instrumentApplicationFunctions(BPatch_binaryEdit* appBin) 
{
    BPatch_image* appImage = appBin->getImage();
    BPatch_function* printfFunc = getPrintFunction(appImage);
    if (printfFunc == nullptr) 
    {
        return;
    }

    std::vector<BPatch_module*> modules;
    appImage->getModules(modules);

    for (auto module : modules) 
    {
        if (module->isSharedLib()) 
        {
            continue;
        }

        std::vector<BPatch_function*> functions;
        module->getProcedures(functions);

        for (auto func : functions) 
        {
            std::string funcName = func->getName();
            if (!isPrintable(funcName)) 
            {
                continue;
            }

            std::vector<BPatch_point*>* entryPoints = func->findPoint(BPatch_entry);
            if (entryPoints == nullptr || entryPoints->empty()) 
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
                appBin->insertSnippet(printfCall, *point);
                cout << "Inserted trace for function: " << funcName << endl;
            }
        }
    }
}

int main(int argc, char** argv) 
{
    if (argc < 2) 
    {
        cerr << "Usage: " << argv[0] << " <input_executable>" << endl;
        return EXIT_FAILURE;
    }

    std::string inputExecutable = string (argv[1]);
    std::string outputExecutable = inputExecutable + "_instrumented";

    BPatch bpatch;
    BPatch_binaryEdit* appBin = bpatch.openBinary(inputExecutable.c_str(), true);
    if (!appBin) 
    {
        cerr << "Failed to open binary for editing" << endl;
        return EXIT_FAILURE;
    }


    instrumentApplicationFunctions(appBin);

    if (!appBin->writeFile(outputExecutable.c_str())) 
    {
        cerr << "Failed to write instrumented binary to output file" << endl;
        return EXIT_FAILURE;
    }

    cout << "Instrumented binary saved as: " << outputExecutable << endl;

    return EXIT_SUCCESS;
}
