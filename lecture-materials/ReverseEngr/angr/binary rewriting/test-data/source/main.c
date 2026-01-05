#include <stdio.h>
#include <string.h>

static char* password = "security";

int main(int argc, char ** argv) 
{
    if (argc < 2)
    {
        return 0;
    }
    
    char* input = argv[1];
    if (strcmp (input, password) == 0)
    {
        printf ("correct password!\r\n");
    }
    else
    {
        printf ("incorrect password!\r\n");
    }

    return 1;
}




