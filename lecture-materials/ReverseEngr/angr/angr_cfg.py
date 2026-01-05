import angr
import sys
import pydot
from networkx.drawing.nx_pydot import write_dot
import os

def analyze_binary(binary_path):

    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    # Locate the main function if available
    main_func = proj.kb.functions.function(name="main")
    if main_func == None:
        print ("No main found!\r\n")
        return

    nx_graph = cfg.graph.subgraph([node for node in cfg.graph\
                       if node.function_address == main_func.addr])

    dot_file = "cfg.dot"
    write_dot(nx_graph, dot_file)
    print(f"CFG saved to {dot_file}")

    png_file = "cfg.png"
    os.system(f"dot -Tpng {dot_file} -o {png_file}")
    print(f"CFG image saved to {png_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python angr_binary_analysis.py path/to/binary")
    else:
        analyze_binary(sys.argv[1])
