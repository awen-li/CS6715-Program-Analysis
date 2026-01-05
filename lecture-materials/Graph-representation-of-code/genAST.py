import ast
import astpretty
from astmonkey import visitors, transformers

source_code = """
def helloWorld(name):
    print(f"Hello, {name}!")

helloWorld("cs6890")
"""

def genPDF (astTree):
    astTree = transformers.ParentChildNodeTransformer().visit(astTree)
    graph = visitors.GraphNodeVisitor()
    graph.visit(astTree)
    graph.graph.write_pdf("ast_output.pdf")

if __name__ == "__main__":
    tree = ast.parse(source_code)
    astpretty.pprint(tree)
    genPDF (tree)

