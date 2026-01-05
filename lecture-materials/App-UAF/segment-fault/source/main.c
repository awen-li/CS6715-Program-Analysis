#include <stdio.h>
#include <stdlib.h>


int main(int argc, char ** argv) 
{
    int *a = (int *)malloc(sizeof(int)*64*1024);

    *a = 5;
    free (a);

    *a = 1024;
    printf ("a = %d\n", *a);
    return 0;
}




