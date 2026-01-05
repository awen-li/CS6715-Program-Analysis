
CCC = $(CC)
LD  = $(CC)

SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj

CFLAGS       = -g -O0 -I$(INCLUDE_PATH) -std=c++11
LD_CFLAGS    = -ldyninstAPI -lcommon -lsymtabAPI -lparseAPI -linstructionAPI -ltbb -ltbbmalloc_proxy -lstdc++ 

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.cpp)
OBJ_FILES    = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

TARGET = callinspect

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS)
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.cpp
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CCC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH) $(TARGET)

