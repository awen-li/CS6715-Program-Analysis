import angr
import claripy
import sys
import pydot
from networkx.drawing.nx_pydot import write_dot
import os

def analyze_binary(binary_path):

    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    main_func = cfg.kb.functions.function(name="main")

    return_addresses = []
    for block in main_func.blocks:
        if block.vex.jumpkind == 'Ijk_Ret':
            return_addresses.append(block.addr)
    print("Identified return addresses:", return_addresses)

    argv1 = claripy.BVS("argv1", 32)
    state = proj.factory.entry_state(args=[binary_path, argv1])

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=return_addresses)

    print("Explored Paths:")
    for stash_name in simgr.stashes:
        if simgr.stashes[stash_name]:
            for path in simgr.stashes[stash_name]:
                print(f"Path in stash '{stash_name}' reached address {hex(path.addr)} with conditions:")
                for constraint in path.solver.constraints:
                    print(f"  - {constraint}")

    results = []
    for found in simgr.found:
        if found.addr in return_addresses:
            return_val = found.solver.eval(argv1)
            results.append((found.addr, return_val))

    print("\nPaths that reached return addresses with concrete input values:")
    for addr, val in results:
        print(f"Path leads to return address {hex(addr)} with argv[1] value: {val}")

    dot_file_path = f"{os.path.basename(binary_path)}_cfg.dot"
    write_dot(cfg.graph, dot_file_path)
    print(f"CFG has been written to {dot_file_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python angr_binary_analysis.py path/to/binary")
    else:
        analyze_binary(sys.argv[1])
