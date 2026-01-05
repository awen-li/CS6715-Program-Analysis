#1. build the print library
cd printFunc
make clean && make
cd -

# 2. build the instrumenter
rm -rf build && mkdir build
cd build
cmake ../instrumenter
make
cp libpfpass.so ../benchmark
cd -
