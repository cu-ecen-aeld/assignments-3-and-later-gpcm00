#include<stdio.h>
#include<stdlib.h>

struct tst
{
    int a;
    int b;
};


void tst_func(o, g)
int o;
char g;
{
    for(int i = o; i > 0; i--)
    {
        printf("%c\n", g);
    }
}
int main()
{
    printf("%ld\n", ((size_t)&((struct tst*)0)->a));
    tst_func(2, 'o');
    return 0;
}