#include <AES.h>
#include "./printf.h"

AES aes ;

byte key[] = "01234567899876543210012345678998";

byte plain[] = "TESTTESTTESTTESTTESTTESTTESTTESTTESTTEST";

//real iv = iv x2 ex: 01234567 = 0123456701234567
unsigned long long int my_iv = 01234567;

void setup ()
{
  Serial.begin (57600) ;
  printf_begin();
  delay(500);
  printf("\n===testng mode\n") ;
  
//  otfly_test () ;
//  otfly_test256 () ;
}

void loop () 
{
  prekey_test () ;
  delay(2000);
}

void prekey (int bits)
{
  aes.iv_inc();
  byte iv [N_BLOCK] ;
  
  aes.calc_size_n_pad(sizeof(plain));
  byte plain_p[aes.get_size()];
  aes.padPlaintext(plain,plain_p);;
  byte cipher [aes.get_size()] ;
  byte check [aes.get_size()] ;
  int blocks = aes.get_size() / N_BLOCK;
  unsigned long ms_key = micros();
  byte succ = aes.set_key (key, bits) ;
  ms_key = micros()-ms_key;
  printf("set_key %i -> %i took %lu micros",bits,(int) succ,ms_key);
  unsigned long ms = micros () ;
  if (blocks == 1)
    succ = aes.encrypt (plain_p, cipher) ;
  else
  {
    aes.get_IV(iv);
    succ = aes.cbc_encrypt (plain_p, cipher, blocks, iv) ;
  }
  ms = micros () - ms ;
  printf("\nencrypt %i took %lu micros",(int)succ,ms);
  ms = micros () ;
  if (blocks == 1)
    succ = aes.decrypt (cipher, plain_p) ;
  else
  {
    aes.get_IV(iv);
    succ = aes.cbc_decrypt (cipher, check, blocks, iv) ;
  }
  ms = micros() - ms ;
  printf("\ndecrypt %i took %lu micros",(int)succ,ms);

  printf("\n\nPLAIN :");
  aes.printArray(plain_p);
  printf("\nCIPHER:");
  aes.printArray(cipher);
  printf("\nCHECK :");
  aes.printArray(check,(bool)true);
  printf("\nIV    :");
  aes.printArray(iv,16);
  printf("\n============================================================\n");
}

void prekey_test ()
{
  prekey (128) ;
}
