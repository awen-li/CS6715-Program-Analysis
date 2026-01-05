#!/bin/bash

Action=$1
Target=countBlock
TargetPath=$(pwd)

# Clean action
if [ "$Action" == "clean" ]; then
    if [ -d "build" ]; then
        rm -rf build
    fi
    exit 0
fi

# Create symbolic link
LLVM_PATH=/home/cs6890/tools
PassDir=$LLVM_PATH/llvm-14.0.6.src/lib/Transforms
if [ ! -L "$PassDir/$Target" ]; then
    cd $PassDir || { echo "Failed to change directory to $PassDir"; exit 1; }
    ln -s $TargetPath $Target
    cd -
fi

# Ensure countBlockPass is in CMakeLists.txt
if ! grep -q "add_subdirectory(countBlock)" $PassDir/CMakeLists.txt; then
    echo "add_subdirectory(countBlock)" >> $PassDir/CMakeLists.txt
fi

# Build LLVM with the new pass
cd $LLVM_PATH/build || { echo "Failed to change directory to $LLVM_PATH/build"; exit 1; }
make -j8


cd $TargetPath
if [ -f "$LLVM_PATH/build/lib/countBlockPass.so" ]; then
    echo "Build Pass countBlockPass successfully"
    cp "$LLVM_PATH/build/lib/countBlockPass.so" ./
else
    echo "Build Pass countBlockPass failed!!"
fi


