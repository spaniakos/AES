#ifndef __AES_H__
#define __AES_H__

#include "AES_config.h"
/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The redistribution and use of this software (with or without changes)
 is allowed without the payment of fees or royalties provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 09/09/2006

 This is an AES implementation that uses only 8-bit byte operations on the
 cipher state.
 */
 
 /* code was modified by george spanos <spaniakos@gmail.com>
 * 16/12/14
 */

class AES
{
 public:

/*  The following calls are for a precomputed key schedule

    NOTE: If the length_type used for the key length is an
    unsigned 8-bit character, a key length of 256 bits must
    be entered as a length in bytes (valid inputs are hence
    128, 192, 16, 24 and 32).
*/
	/** \fn AES()
	* \brief AES constructor
	* 
	* This function initialized an instance of AES.
	*/
	AES();
		
	/** Set the cipher key for the pre-keyed version. 
	 *  @param key[] pointer to the key string.
	 *  @param keylen Integer that indicates the length of the key.
	 *  @note NOTE: If the length_type used for the key length is an unsigned 8-bit character, 
	 *  a key length of 256 bits must be entered as a length in bytes 
	 *  (valid inputs are hence 128, 192, 16, 24 and 32).
	 *
	 */
	byte set_key (byte key[], int keylen) ;
	
	/** clean up subkeys after use.
	 * 
	 */ 
	void clean () ;  // delete key schedule after use
	
	/** copying and xoring utilities.
	 *  @param *dest byte pointer of the destination array.
	 *  @param *src byte pointer of the source array.
	 *  @param n byte, indicating the sizeof the bytes to be copied.
	 *  @note this is an alternative for memcpy(void *s1,const void *s2, site_t n),
	 *  i have not updated the function in the implementation yet, but it is considered a future plan.
	 *
	 */
	void copy_n_bytes (byte * dest, byte * src, byte n) ;

	/** Encrypt a single block of 16 bytes .
	 *  @param plain[N_BLOCK] Array of the plaintext.
	 *  @param cipher[N_BLOCK] Array of the ciphertext.
	 *  @note The N_BLOCK is defined in AES_config.h as,
	 *  @code #define N_ROW                   4
	 *		  #define N_COL                   4
	 *		  #define N_BLOCK   (N_ROW * N_COL)
	 *	@endcode
	 *  Changed to that will change the Block_size.
	 *  @Return 0 if SUCCESS or -1 if FAILURE
	 *
	 */
	byte encrypt (byte plain [N_BLOCK], byte cipher [N_BLOCK]) ;
	
	/** CBC encrypt a number of blocks (input and return an IV).
	 *  
	 *  @param *plain Pointer, points to the plaintex.
	 *  @param *cipher Pointer, points to the ciphertext that will be created.
	 *  @param n_block integer, indicated the number of blocks to be ciphered.
	 *  @param iv[N_BLOCK] byte Array that holds the IV (initialization vector).
	 *  @Return 0 if SUCCESS or -1 if FAILURE
	 *
	 */
	byte cbc_encrypt (byte * plain, byte * cipher, int n_block, byte iv [N_BLOCK]) ;


	/**  Decrypt a single block of 16 bytes 
	 *  @param cipher[N_BLOCK] Array of the ciphertext.
	 *  @param plain[N_BLOCK] Array of the plaintext.
	 *  @note The N_BLOCK is defined in AES_config.h as,
	 *  @code #define N_ROW                   4
	 *		  #define N_COL                   4
	 *		  #define N_BLOCK   (N_ROW * N_COL)
	 *	@endcode
	 *  Changed to that will change the Block_size.
	 *  @Return 0 if SUCCESS or -1 if FAILURE
	 *
	 */
	byte decrypt (byte cipher [N_BLOCK], byte plain [N_BLOCK]) ;
	
	/** CBC decrypt a number of blocks (input and return an IV) 
	 *  
	 *  @param *cipher Pointer, points to the ciphertext that will be created.
	 *  @param *plain Pointer, points to the plaintex.
	 *  @param n_block integer, indicated the number of blocks to be ciphered.
	 *  @param iv[N_BLOCK] byte Array that holds the IV (initialization vector).
	 *  @Return 0 if SUCCESS or -1 if FAILURE
	 *
	 */
	byte cbc_decrypt (byte * cipher, byte * plain, int n_block, byte iv [N_BLOCK]) ;
		
	/** Sets IV (initialization vector) and IVC (IV counter).
	 *  This function changes the ivc and iv variables needed for AES.
	 *
	 *  @param IVC int or hex value of iv , ex. 0x0000000000000001
	 *  @note example:
	 *  @code unsigned long long int my_iv = 01234567; @endcode
	*/
	void set_IV(unsigned long long int IVCl);
		
	/** increase the iv (initialization vector) and IVC (IV counter) by 1
	 * 
	 *  This function increased the VI by one step in order to have a different IV each time
	 * 
	*/
	void iv_inc();
		
	/** Getter method for size
	 * 
	 * This function return the size
	 * @return an integer, that is the size of the of the padded plaintext,
	 * thus, the size of the ciphertext.
	 */
	int get_size();
	
	/** Getter method for IV
	* 
	* This function return the IV
	* @param out byte pointer that gets the IV.
	* @return none, the IV is writed to the out pointer.
	*/
	void get_IV(byte* out);
		
	/** Calculates the size of the plaintext and the padding.
	 * 
	 * Calculates the size of theplaintext with the padding
	 * and the size of the padding needed. Moreover it stores them in their class variables.
	 * 
	 * @param p_size the size of the byte array ex sizeof(plaintext)
	*/
	void calc_size_n_pad(int p_size);
	
	/** Pads the plaintext
	 * 
	 * This function pads the plaintext and returns an char array with the 
	 * plaintext and the padding in order for the plaintext to be compatible with 
	 * 16bit size blocks required by AES
	 * 
	 * @param in the string of the plaintext in a byte array
	 * @param out The string of the out array.
	 * @return no return, The padded plaintext is stored in the out pointer.
	 */
	void padPlaintext(void* in,byte* out);
		
	/** Check the if the padding is correct.
	 * 
	 * This functions checks the padding of the plaintext.
	 * 
	 * @param in the string of the plaintext in a byte array
	 * @param the size of the string
	 * @return true if correct / false if not
	 */
	bool CheckPad(byte* in,int size);

	/** Prints the array given.
	 * 
	 * This function prints the given array and pad, 
	 * It is mainlly used for debugging purpuses or to output the string.
	 * 
	 * @param output[] the string of the text in a byte array
	 * @param p_pad optional, used to print with out the padding characters
	*/
	void printArray(byte output[],bool p_pad = false);
	
	/** Prints the array given.
	 * 
	 * This function prints the given array in Hexadecimal.
	 * 
	 * @param output[] the string of the text in a byte array
	 * @param sizel the size of the array.
	*/
	void printArray(byte output[],int sizel);
	
	void do_aes_encrypt(byte *plain,int size_p,byte *cipher,byte *key, int bits);
	void do_aes_dencrypt(byte *cipher,int size_c,byte *plain,byte *key, int bits, byte ivl [N_BLOCK]);
	void set_size(int sizel);
	byte cbc_encrypt (byte * plain, byte * cipher, int n_block) ;
	#if defined(AES_LINUX)
		/**
		 * used in linux in order to retrieve the time in milliseconds.
		 *
		 * @return returns the milliseconds in a double format.
		 */
		double millis();
	#endif
 private:
  int round ;/**< holds the number of rounds to be used. */
  byte key_sched [KEY_SCHEDULE_BYTES] ;/**< holds the pre-computed key for the encryption/decrpytion. */
  unsigned long long int IVC;/**< holds the initialization vector counter in numerical format. */
  byte iv[16];/**< holds the initialization vector that will be used in the cipher. */
  int pad;/**< holds the size of the padding. */
  int size;/**< hold the size of the plaintext to be ciphered */
  #if defined(AES_LINUX)
	timeval tv;/**< holds the time value on linux */
	byte arr_pad[15];/**< holds the hexadecimal padding values on linux */
  #else
	byte arr_pad[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };/**< holds the hexadecimal padding values */
  #endif
} ;


#endif
