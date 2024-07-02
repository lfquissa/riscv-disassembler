// Assume que string possui tamanho suficiente para guardar 
// os digitos e o '\0'
void int_to_unsigned_dec_str(unsigned int num, char *str);

void int_to_signed_dec_str(unsigned int num, char *str);

// Assume string possui tamanho size_hex + 1 e coloca '\0' na ultima posiçao
void int_to_padded_hex(unsigned int decimal, char* hex, int size_hex);

// Assume que hex é grande o bastante
void int_to_hex(unsigned int decimal, char *hex);

// Assume string possui tamanho size_hex + 1 e coloca '\0' na ultima posiçao
void change_hex_endian(char *hex, char *big_hex, int size_hex);

// Assume string possui tamanho size_hex + 1 e coloca '\0' na ultima posiçao
unsigned int hex_to_uint(char *hex, int size_hex);

int num_digits(unsigned int n);

int num_hex_digits(unsigned int n);

unsigned int my_pow(int base, int exp);
