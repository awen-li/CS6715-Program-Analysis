#include <stdio.h>
#include <string.h>

static char* password = "security";


void funcC ()
{
    return;
}

void funcB ()
{
    funcC ();
    return;
}



int funcA (char* input)
{
    if (strcmp (input, password) == 0)
    {
        printf ("correct password!\r\n");
        funcB ();
        return 0;
    }
    else
    {
        printf ("incorrect password!\r\n");
        return 1;
    } 
}

int main(int argc, char ** argv) 
{
    if (argc < 2)
    {
        return 0;
    }

    char* input = argv[1];
    
    return funcA (input);
}




