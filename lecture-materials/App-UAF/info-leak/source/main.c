#include <stdio.h>
#include <stdlib.h>


int main(int argc, char ** argv) 
{
    int *a = (int *)malloc(sizeof(int)*16);

    *a = 5;
    free (a);

    printf ("a = %d\n", *a);   
    return 0;
}




