#include<stdio.h>

int g1 = 0;
int g2;

int direct_call(int value)
{
    int ret = value * 2 + 1;
    return ret;
}

int main(int argc, char **argv)
{
    printf("hello world!");
    if (argc > 1)
        return direct_call(argc);
    else
        return (argc + 1);
}
