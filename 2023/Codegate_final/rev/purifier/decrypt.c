#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

unsigned char SBOX[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3F, 0x34, 0x35, 
  0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 
  0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
  0x19, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x1A, 0x1B, 0x1C, 
  0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 
  0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 
  0x31, 0x32, 0x33
};
typedef int64_t __int64;
typedef int16_t __int16;

int sbox(char *astring, int a2, char *dest, int a4) {
      int v4; // r11d
  int v6; // r10d
  char v7; // al
  __int64 i; // rdx
  __int64 j; // rdx
  __int64 v10; // rax
  __int16 v11; // r8
  char v12; // al
  char v13; // al

  v4 = 0;
  v6 = a2;
  v7 = 0;
    while ( 1 )
  {
    while ( ((*astring - 9) & 0xFA) == 0 && *astring != 14 )
    {
      ++astring;
      --v6;
    }
    if ( v6 < 2 || v4 >= (int)a4 )
      break;
    v10 = *astring;
    astring += 2;
    ++dest;
    ++v4;
    v11 = SBOX[*(astring - 1)] << 12;
    *(dest - 1) = ((SBOX[*(astring - 1)] << 12) | (unsigned int)(SBOX[v10] << 18)) >> 16;
    v12 = *astring;
    if ( *astring )
    {
      if ( v12 != 61 )
      {
        if ( v4 >= (int)a4 )
          return 0;
        ++dest;
        ++astring;
        v11 |= SBOX[v12] << 6;
        ++v4;
        *(dest - 1) = ((uint16_t)(v11)) >> 8;
      }
      v13 = *astring;
      if ( *astring )
      {
        if ( v13 != 61 )
        {
          if ( v4 >= (int)a4 )
            return 0;
          ++dest;
          ++astring;
          ++v4;
          *(dest - 1) = SBOX[v13] | v11;
        }
      }
    }
    v6 -= 4;
    if ( v6 <= 0 )
      return v4;
  }
}

void xor(char *input, int length) {
    char *code = "C0D39453";
    for (int i = 0; i < length; i++) {
        input[i] = input[i] ^ code[i % 8];
    }
}

void decrypt_string(char *input) {
    char *x = strdup(input);
    int length = strlen(x);
    char *y = calloc(length, 1);
    for (int i = 0; i < length; i += 2) 
        y[i] = 0x20;
    sbox(x, length, y, length);

    int new_len = strlen(y);
    xor(y, new_len);

    for (int i = 0; i < new_len / 2; i++) {
        printf("%c", y[i * 2]);
    }
    printf("\n");
    free(x);
    free(y);
}

int main() {

    char *arr[] = {
    "cDA=",
    "cTA=",
    "EzAxM0s0XDMlMC0zXDRHM2MwEjNcNEczKjAiM0A0FTMAMCszVDR",
    "FMy8wITNNNFAzJzA=",
    "bDAnMxk0",
    "cjA=",
    "FTAhM0s0XDMlMD0z",
    "bDBlM3k0FjNnMGsz",
    "ZzA=",
    "IDArM100UDMkMCUzTTRQM3EwdDMLNAYz",
    "KzAwM000RTMwMH4zFjQaMyEwJTNdNBszJDAxM0A0RjNtMCozXDRDMyYwNjMXNFczJjBqM1w0TTM3MC0zVzQbMyAwMDM=",
    "IDApM100GzMmMDwzXDQ=",
    "PjA=",
    "ODA=",
    };

    for (int i = 0; i < sizeof(arr) / sizeof(char*); i++) {
        printf("%s\n-> ", arr[i]);
        decrypt_string(arr[i]);
    }
}
