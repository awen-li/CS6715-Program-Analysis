#include <stdio.h>
#include <stdlib.h>


int main(int argc, char ** argv) 
{
    if (argc < 3)
    {
        return 0;
    }
    
    int a = atoi (argv[1]);
    int b = atoi (argv[2]);

    printf ("Hello LLVM: %d\n", a*b);

    return 0;
}




