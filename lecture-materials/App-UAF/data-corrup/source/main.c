#include <stdio.h>
#include <stdlib.h>


int main(int argc, char ** argv) 
{
    int *a = (int *)malloc(sizeof(int)*4);

    *a = 5;
    free (a);
    
    int *b = malloc (sizeof(int));
    *b = 10;

    *a = 1024;
    printf ("b = %d\n", *b);   
    return 0;
}




