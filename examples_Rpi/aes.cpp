#include <AES.h>
#include "printf.h"

AES aes;

void prekey_test ();
void prekey (int bits, int blocks);

byte key[] = "01234567899876543210012345678998";

byte plain[] = "TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST";
int plainLength = sizeof(plain)-1;  // don't count the trailing /0 of the string !
int padedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;

//real iv = iv x2 ex: 01234567 = 0123456701234567
unsigned long long int my_iv = 01234567;

int main(int argc, char** argv)
{
  printf("\n===testing mode\n") ;

  for (int i=0;i<1;i++){
    prekey_test () ;
  }
}

void prekey (int bits)
{
  byte iv [N_BLOCK] ;
  byte plain_p[padedLength];
  byte cipher[padedLength];
  aes.do_aes_encrypt(plain,plainLength,cipher,key,bits);
  aes.get_IV(iv);
  aes.do_aes_decrypt(cipher,aes.get_size(),plain_p,key,bits,iv);
  //normally u have sizeof(cipher) but if its in the same sketch you cannot determin it dynamically

  printf("\n\nPLAIN :");
  aes.printArray(plain);
  printf("\nCIPHER:");
  aes.printArray(cipher);
  printf("\nPlain2:");
  aes.printArray(plain_p);
  printf("\n============================================================\n");
}

void prekey_test ()
{
  prekey (128) ;
}
