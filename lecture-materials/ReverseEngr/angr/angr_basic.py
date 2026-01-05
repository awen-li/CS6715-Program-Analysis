import angr
import sys
import pydot
from networkx.drawing.nx_pydot import write_dot
import os

def analyze_binary(binary_path):

    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    print("Binary architecture:", proj.arch)
    print("Entry point:", hex(proj.entry))

    for addr, func in cfg.kb.functions.items():
        print(f"Function {func.name} at address {hex(addr)}")

    for section in proj.loader.main_object.sections:
        print(f"Section {section.name}: {hex(section.vaddr)} (size {section.memsize})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python angr_binary_analysis.py path/to/binary")
    else:
        analyze_binary(sys.argv[1])
