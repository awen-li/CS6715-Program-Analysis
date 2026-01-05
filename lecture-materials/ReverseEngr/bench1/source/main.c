#include<stdio.h>

int g1 = 0;
int g2;

int direct_call(int val)
{
    return val++;
}

// hello world program
int main(int argc, char **argv)
{
    printf("hello world!");
    return direct_call(argc);
}

