#include <stdio.h>
#include <stdlib.h>


int main(int argc, char ** argv) 
{
    if (argc < 2)
    {
        return 0;
    }
    
    int i = atoi (argv[1]);
    if (i == 1)
    {
        printf ("helloworld 5890\r\n");
    }
    else
    {
        printf ("helloworld 6890\r\n");
    }

    return 1;
}




