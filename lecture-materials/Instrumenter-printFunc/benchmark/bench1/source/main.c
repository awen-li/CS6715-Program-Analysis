#include <stdio.h>
#include <stdlib.h>

unsigned Getpasswd (unsigned char Key);

int FuncA (int Index)
{
    return Index*5 + 1;
}

unsigned FuncB (unsigned char Value)
{
    unsigned Pwd = 0;
    /* y = x*x + 5x + 1*/
    unsigned FValue = Value *Value + 5*Value - 100;
    switch (FValue)
    {
        case 0:
        {
            Pwd = 0;
            break;
        }
        case 65535:
        {
            Pwd = 2;
            break;
        }
        case 999999:
        {
            Pwd = Getpasswd (4);
            break;
        }
        default:
        {
            Pwd = Getpasswd (4);
            exit (0);
        }
    }
    return Pwd;
}


int main(int argc, char ** argv) 
{
    int Pwd = 0;
    int Value = FuncA (argc);

    if (Value >= 4 && Value <= 16)
    {
        Pwd = Getpasswd (Value);
    }
    else
    {
        Pwd = FuncB (Value);        
    }
    
    return Pwd;
}




