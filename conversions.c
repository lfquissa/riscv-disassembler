#define SIZE_BIN 34
#define SIZE_HEX 8
#include "conversions.h"

void int_to_signed_dec_str(unsigned int num, char *str)
{
    int digit;
    if (num & (1U << 31))
    {
        num = (~num) + 1;
        str[0] = '-';

        int digits = num_digits(num);
        for (int i = digits; i >= 1; i--) 
        {
            digit = num %10;
            num = num/10;
            str[i] = digit + '0';
        }
        str[digits+1] = '\0';
    }
    else
    {
        int digits = num_digits(num);
        for (int i = digits-1; i >= 0; i--) 
        {
            digit = num %10;
            num = num/10;
            str[i] = digit + '0';
        }
        str[digits] = '\0';
    }
}

// Assume que string possui tamanho suficiente para guardar 
// os digitos e o '\0'
void int_to_unsigned_dec_str(unsigned int num, char *str)
{
    int digit;
    int digits = num_digits(num);

    for (int i = digits-1; i >=0; i--)
    {
        digit = num%10;
        num = num/10;
        str[i] = digit + '0';
    }
    str[digits] = '\0';
}

// Assume string possui tamanho size_hex + 1 e coloca '\0' na ultima posiçao
unsigned hex_to_uint(char *hex, int size_hex)
{
    unsigned int decimal = 0;
    int digit;

    for (int i = 2; i < size_hex; i++)
    {
        if (hex[i]>= '0' && hex[i] <= '9')
        {
            digit = (hex[i] - '0');
        }
        else if (hex[i] >= 'a' && hex[i] <='f') 
        {
            digit = (10 + (hex[i] - 'a'));
        }
        decimal += digit*my_pow(16, ((size_hex - 1) - 2) - (i-2));
    }
    return decimal;
}

// Assume string possui tamanho size_hex + 1 e coloca '\0' na ultima posiçao
void change_hex_endian(char *hex, char *big_hex, int size_hex)
{
    for(int i = 0, j = size_hex - 2; i < size_hex; i += 2, j -= 2 )
    {
        big_hex[i] = hex[j];
        big_hex[i+1] = hex[j+1];
    }
    big_hex[size_hex] = '\0';
}

// Assume string possui tamanho size_hex + 1 e coloca '\0' na ultima posiçao
void int_to_padded_hex(unsigned int decimal, char* hex, int size_hex)
{
    for (int i = size_hex -1; i >= 0; i -= 1 )
    {
        int digit = decimal % 16; 
        decimal = decimal / 16;
        if (digit >= 1 && digit <= 9)
            hex[i] = digit + '0';
        else if (digit >= 10 && digit <= 15)
        {
            digit = 'a' + (digit - 10);
            hex[i] = digit; 
        }
        else
            hex[i] = '0';
    }
    hex[size_hex] = '\0';
}

// Assume que hex é grande o bastante
void int_to_hex(unsigned int decimal, char *hex)
{
    int digit;
    int n_digits = num_hex_digits(decimal);

    for (int i = n_digits -1; i >= 0; i -= 1 )
    {
        digit = decimal % 16; 
        decimal = decimal / 16;
        if (digit >= 1 && digit <= 9)
            hex[i] = digit + '0';
        else if (digit >= 10 && digit <= 15)
        {
            digit = 'a' + (digit - 10);
            hex[i] = digit; 
        }
        else
            hex[i] = '0';
    }
    hex[n_digits] = '\0';
}

unsigned int my_pow(int base, int exp)
{
    int res = 1;
    for (int i = 0; i < exp; i++)
        res *= base;
    return res;
}

int num_digits(unsigned int n)
{
    if (n == 0) return 1;

    if (n & (1U << 31))
        n = ~n +1;

    int digit = 0;
    while(n != 0)
    {
        digit++;
        n = n/10;
    }
    return digit;
    
}

int num_hex_digits(unsigned int n)
{
    if (n == 0) return 1;
    else
    {
        int digit = 0;
        while (n != 0)
        {
            digit++;
            n = n/16;
        }
        return digit;
    }
}
