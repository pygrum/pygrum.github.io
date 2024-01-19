#include <string.h>
#include <stdio.h>

typedef struct pii {
    char name[10];
    int age;
    char PAN[17]; // We use a size of 17 to include the null terminator
} pii;

void init_pii(pii* p_pii)
{
    strcpy(p_pii->name, "bob");
    p_pii->age = 20; 
    strcpy(p_pii->PAN, "1234567890123456");
}

int main()
{
    pii bob_pii;
    init_pii(&bob_pii);

    printf("Name: %s\nAge: %d\nPAN: %s\n", bob_pii.name, bob_pii.age, bob_pii.PAN);
    return 0;
}