#include <AES.h>
#include "printf.h"

AES aes;

void prekey_test ();
void prekey (int bits, int blocks);

byte key[] = "01234567899876543210012345678998";

byte plain[] = "TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST";

//real iv = iv x2 ex: 01234567 = 0123456701234567
unsigned long long int my_iv = 01234567;

byte cipher [4*N_BLOCK] ;
byte check [4*N_BLOCK] ;

int main(int argc, char** argv)
{
  printf("\n===testng mode\n") ;

  for (int i=0;i<10;i++){
    prekey_test () ;
  }
}

void prekey (int bits, int blocks)
{
  aes.iv_inc();
  byte iv [N_BLOCK] ;
  
  aes.calc_size_n_pad(sizeof(plain));
  byte plain_p[aes.get_size()];
  aes.padPlaintext(plain,plain_p);
  
  unsigned long ms = aes.millis();
  byte succ = aes.set_key (key, bits) ;
  ms = aes.millis()-ms;
  printf("set_key %i -> %i took %lu ms",bits,(int) succ,ms);
  ms = aes.millis () ;
  if (blocks == 1)
    succ = aes.encrypt (plain_p, cipher) ;
  else
  {
    aes.get_IV(iv);
    succ = aes.cbc_encrypt (plain_p, cipher, blocks, iv) ;
  }
  ms = aes.millis () - ms ;
  printf("\nencrypt %i took %lu ms",(int)succ,ms);
  ms = aes.millis () ;
  if (blocks == 1)
    succ = aes.decrypt (cipher, plain_p) ;
  else
  {
    aes.get_IV(iv);
    succ = aes.cbc_decrypt (cipher, check, blocks, iv) ;
  }
  ms = aes.millis () - ms ;
  printf("\ndecrypt %i took %lu ms",(int)succ,ms);

  printf("\n\nPLAIN :");
  aes.printArray(plain_p);
  printf("\nCIPHER:");
  aes.printArray(cipher);
  printf("\nCHECK :");
  aes.printArray(check,(bool)true);
  printf("\nIV    :");
  aes.printArray(iv,16);
  
  bool ok = aes.CheckPad(plain_p,sizeof(plain_p));
  if (ok)
    printf("padding ok!\n");
  else
    printf("padding corrupted!\n");
  printf("\n============================================================\n");
}

void prekey_test ()
{
  prekey (128, 4) ;
}