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
	* This function initialized an instance of AES
	*/
	AES();
		
	/**  Set the cipher key for the pre-keyed version 
	 * 
	 */
	byte set_key (byte key[], int keylen) ;
	
	/** clean up subkeys after use.
	 * 
	 */ 
	void clean () ;  // delete key schedule after use
	
	/** copying and xoring utilities 
	 * 
	 */
	void copy_n_bytes (byte * dest, byte * src, byte n) ;

	/**  Encrypt a single block of 16 bytes 
	 * 
	 */
	byte encrypt (byte plain [N_BLOCK], byte cipher [N_BLOCK]) ;
	
	/** CBC encrypt a number of blocks (input and return an IV) 
	 * 
	 */
	byte cbc_encrypt (byte * plain, byte * cipher, int n_block, byte iv [N_BLOCK]) ;


	/**  Decrypt a single block of 16 bytes 
	 * 
	 */
	byte decrypt (byte cipher [N_BLOCK], byte plain [N_BLOCK]) ;
	
	/** CBC decrypt a number of blocks (input and return an IV) 
	 * 
	 */
	byte cbc_decrypt (byte * cipher, byte * plain, int n_block, byte iv [N_BLOCK]) ;
		
	/** \fn void change_IV(unsigned long long int IVCl);
	* \brief Change IVC and iv
	* 
	* This function changes the ivc and iv variables needed for AES
	* 
	* \param IVC int or hex value of iv , ex. 0x0000000000000001
	*/
	void set_IV(unsigned long long int IVCl);
		
	/** \fn voiv_inc()
	* \brief inrease the IVC and iv but 1
	* 
	* This function increased the VI by one step in order to have a different IV each time
	* 
	*/
	void iv_inc();
		
	/** \fn get_size()
	* \brief getter method for size
	* 
	* This function return the size
	* 
	*/
	int get_size();
	
	/** \fn get_IV(byte* out)
	* \brief getter method for IV
	* 
	* This function return the IV
	* 
	*/
	void get_IV(byte* out);
		
	/** \fn calc_size_n_pad(uint8_t p_size)
	* \brief calculates the size of the plaintext and the padding
	* 
	* calculates the size of theplaintext with the padding
	* and the size of the padding needed. Moreover it stores them in their variables.
	* 
	* \param m_plaintext the string of the plaintext in a byte array
	* \param p_size the size of the byte array ex sizeof(plaintext)
	*/
	void calc_size_n_pad(int p_size);
	
	/** \fn padPlaintext(void* in,byte* out)
	* \brief pads the plaintext
	* 
	* This function pads the plaintext and returns an char array with the 
	* plaintext and the padding in order for the plaintext to be compatible with 
	* 16bit size blocks required by AES
	* 
	* \param in the string of the plaintext in a byte array
	*/
	void padPlaintext(void* in,byte* out);
		
	/** \fn CheckPad(void* in,int size)
	* \brief check the if the padding is correct
	* 
	* This functions checks the padding of the plaintext.
	* 
	* \param in the string of the plaintext in a byte array
	* \param the size of the string
	* \return true if correct / false if not
	*/
	bool CheckPad(byte* in,int size);

	/** \fn tprintArray(byte output[],bool p_pad = false)
	* \brief Prints the array given
	* 
	* This function prints the given array with size equal \var size
	* and pad equal \var pad. It is mainlly used for debugging purpuses or to output the string.
	* 
	* \param output the string of the plaintext in a byte array
	* \param p_pad optional, used to print with out the padding characters
	*/
	void printArray(byte output[],bool p_pad = false);
	void printArray(byte output[],int sizel);
	#if defined(AES_LINUX)
		unsigned long millis();
	#endif
 private:
  int round ;
  byte key_sched [KEY_SCHEDULE_BYTES] ;
  unsigned long long int IVC;
  byte iv[16];
  int pad;
  int size;
  #if defined(AES_LINUX)
	timeval tv;
	byte arr_pad[15];
  #else
	byte arr_pad[15] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
  #endif
} ;


#endif
