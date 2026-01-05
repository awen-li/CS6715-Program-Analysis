#!/bin/bash
set -e
BCFile="demo.bc"

for item in bench*
do
	echo "[*] Generating LLVM IR for $item..."
    cd $item && make clean && make && cd ..
    cp $item/$BCFile ./
    echo

    echo "[*] Running instrumentation pass..."
    opt -load-pass-plugin ./libpfpass.so -passes=pfpass $BCFile -o instrumented.bc
    echo

    echo "[*] Compiling instrumented program..."
    clang instrumented.bc -o demo -lprintfunc
    echo

    echo "[*] Running instrumented binary:"
    ./demo
done




