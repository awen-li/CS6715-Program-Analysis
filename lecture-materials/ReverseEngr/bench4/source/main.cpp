#include<map>

void function1(std::map<int, int>& m)
{
    for (int i = 0; i < 10; ++i) {
        m[0] = i * 2;
    }
}

void function2(std::map<int, int>& m)
{
    auto &index0 = m[0];
    for (int i = 0; i < 10; ++i) {
        index0 += i * 2;
    }
}

int main(int argc, char **argv)
{
    std::map<int, int> m;
    m[0] = 2;
    
    function1 (m);
    function2 (m);

    return 0;
}
