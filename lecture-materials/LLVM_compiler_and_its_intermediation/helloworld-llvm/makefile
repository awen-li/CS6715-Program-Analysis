# Compiler and linker
CC = clang
LD = clang

# Paths
SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj

# Flags
CFLAGS       = -g -emit-llvm -I$(INCLUDE_PATH)
LD_CFLAGS    =

# Collect all .c files under SOURCE_PATH
SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.c)

# Convert each .c to a corresponding .bc file under OBJ_PATH
BC_FILES = $(patsubst $(SOURCE_PATH)/%.c, $(OBJ_PATH)/%.bc, $(SOURCE_FILES))

# Final executable name
TARGET = demo

.PHONY: all clean

all: $(TARGET)

#######################################
# 1. Build each .bc from each .c
#######################################
$(OBJ_PATH)/%.bc: $(SOURCE_PATH)/%.c
	@mkdir -p $(OBJ_PATH)
	$(CC) $(CFLAGS) -c -o $@ $<

#######################################
# 2. Link all .bc files into merged.bc
#######################################
$(TARGET).bc: $(BC_FILES)
	llvm-link -o $@ $^

#######################################
# 3. Compile merged.bc to native .o
#######################################
$(OBJ_PATH)/merged.o: $(TARGET).bc
	llc -filetype=obj -o $@ $<

#######################################
# 4. Link the final executable
#######################################
$(TARGET): $(OBJ_PATH)/merged.o
	$(LD) -o $@ $< $(LD_CFLAGS)

clean:
	rm -rf $(OBJ_PATH) $(TARGET)
