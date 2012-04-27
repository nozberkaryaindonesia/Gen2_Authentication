/*
Author: Qi Chai
Date:   4/17/2012
This is a tweaked implementation of WG-7 stream cipher as proposed by Y. Luo, Q. Chai, G., X. Lai
in the paper entitled "A Lightweight Stream Cipher WG-7 for RFID Encryption and Authentication" in 2010.

The current implementation has been modified in several ways:
# to be work with a WISP tag:
1. the IV is of 35-bit (RN16_T, RN16_R and other 4 padding zero bits) 
2. the hard coded key is of 126-bit
3. the key scheduling is simplified
# different choose of WG-7 parameters due to the recent attack against its original version
*/

#include "msp430x21x2.h"

/*
characteristic polynomial of GF(2^7): x^7 + x + 1

primitve polynomial the 23-stage LFSR over GF(2^7):
x^23 + x^20 + x^18 + x^15 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^7 + x^5 + x + 80

Resilient-Basis for WG-7
A=
[1 0 0 0 1 1 0]
[0 0 0 0 1 1 0]
[0 0 0 1 0 1 0]
[1 0 1 1 0 1 1]
[0 0 0 1 0 0 1]
[1 1 1 0 1 1 0]
[0 1 0 1 1 0 0]
decimation = 47   resiliency= 1   AI= 4   nonlinearity= 52        degree 5
*/


const unsigned int WGTrans[128] =
{
  0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 
  1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 
  1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 
  0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 
  0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 
  0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 
  0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 
  1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0
};

/*
WGPerm[128] = [0, a^6 + a^5 + a^3 + 1, a^4 + a^3 + a + 1, a^5 + a^2, a^6 + a^5 + a^4 + a^3 + a^2, a^6 + a^4 + 1, a^6 + a^5 + a + 1, a^6 + a^2 + a + 1, a^6 + a^3 + 1, a^6 + a^2 + 1, a^5 + a^4 + 1, a^2, a^2 + a, a^6 + a^5 + a^4 + a, a^6 + a^4 + a^3 + a^2 + a, a^6 + a^5 + a, a^4 + a^2 + a + 1, a^5 + a^4 + a^2, a^6 + a^5 + a^4 + 1, a^6 + a^4 + a, a^4 + a^2 + a, a^5 + a^2 + 1, a^6 + a^5 + a^4 + a^3 + a^2 + 1, a^6 + a^4 + a^3 + a + 1, a^6 + a^5 + a^3 + a^2 + a + 1, a^3 + 1, a^6 + a^5 + a^4, a^6 + a^3 + a^2 + a + 1, a, a^6 + a^5 + a^4 + a^3 + a^2 + a, a^5 + a, a^2 + a + 1, a^3 + a^2 + a + 1, a^4 + a^3 + a^2, a^6 + a^3 + a^2 + a, a^5 + a^3 + a^2, a^4 + a^3 + 1, a^3 + a^2 + a, a^5 + a^4 + a^3 + a^2 + a + 1, a^6 + a^5 + a^2 + a, a^6, 1, a^6 + a + 1, a^6 + a^3 + a, a + 1, a^6 + a^3 + a + 1, a^6 + a^5 + a^4 + a^3 + a, a^4 + a^3, a^6 + a^3 + a^2, a^6 + a^4 + a^3 + a, a^5 + a^4 + a^2 + a + 1, a^5 + a + 1, a^4 + a^3 + a^2 + 1, a^5 + a^4 + a^3 + a^2, a^5 + a^3 + 1, a^5 + a^3 + a^2 + 1, a^4, a^5 + a^2 + a + 1, a^6 + a^5 + a^4 + a^3 + 1, a^6 + a^4 + a^2 + 1, a^5 + a^3 + a^2 + a, a^6 + a^5 + a^4 + a^2 + a, a^6 + a^2, a^6 + a^2 + a, a^4 + a^3 + a^2 + a, a^5 + a^3 + a, a^6 + a^4 + a^3 + 1, a^3 + a^2, a^5, a^6 + a^5 + a^4 + a^3 + a^2 + a + 1, a^3 + a^2 + 1, a^6 + a^5 + a^4 + a^3 + a + 1, a^6 + a^5 + a^4 + a^3, a^6 + a^5 + a^2 + 1, a^5 + a^4 + a^3 + 1, a^5 + a^4 + a^3 + a^2 + a, a^6 + a^5 + a^3 + a + 1, a^6 + a^4 + a^2, a^5 + a^4 + a, a^5 + a^4 + a^3 + a + 1, a^6 + a^5 + a^4 + a^2, a^6 + a^5 + a^3 + a^2 + 1, a^6 + a, a^4 + a, a^5 + a^4, a^6 + a^3 + a^2 + 1, a^6 + a^5 + a^2, a^5 + a^4 + a^2 + 1, a^5 + 1, a^6 + a^4 + a^3 + a^2, a^5 + a^4 + a^3, a^6 + a^3, a^6 + a^5 + a^4 + a^2 + 1, a^4 + a^3 + a, a^6 + a^4 + a^3 + a^2 + 1, a^2 + 1, a^3, a^6 + a^4 + a^3 + a^2 + a + 1, a^5 + a^4 + a + 1, a^6 + a^5, a^4 + a^2, a^5 + a^3 + a + 1, a^3 + a, a^6 + a^5 + a^3 + a^2, a^6 + a^4 + a^2 + a + 1, a^6 + a^5 + 1, a^6 + a^5 + a^3, a^4 + a^2 + 1, a^6 + a^5 + a^4 + a^2 + a + 1, a^6 + a^4 + a + 1, a^5 + a^4 + a^2 + a, a^4 + a + 1, a^6 + a^5 + a^4 + a + 1, a^6 + a^4 + a^2 + a, a^4 + a^3 + a^2 + a + 1, a^6 + a^4, a^5 + a^3, a^5 + a^4 + a^3 + a, a^6 + a^5 + a^2 + a + 1, a^5 + a^4 + a^3 + a^2 + 1, a^4 + 1, a^5 + a^3 + a^2 + a + 1, a^6 + a^5 + a^3 + a, a^6 + a^4 + a^3, a^6 + a^5 + a^3 + a^2 + a, a^6 + 1, a^3 + a + 1, a^5 + a^2 + a] 
*/
const unsigned int WGPerm[128] =
{
  0, 66, 118, 7, 32, 82, 126, 121, 109, 25, 101, 40, 72, 52, 111, 87, 
  2, 100, 125, 27, 43, 46, 9, 110, 10, 117, 84, 37, 96, 64, 79, 97, 
  61, 23, 12, 91, 22, 20, 113, 127, 24, 41, 81, 36, 73, 13, 104, 63, 
  108, 71, 45, 102, 62, 56, 90, 114, 99, 78, 33, 122, 59, 28, 48, 80, 
  119, 19, 14, 116, 47, 105, 93, 65, 8, 54, 57, 88, 34, 83, 44, 89,
  124, 106, 120, 3, 76, 69, 31, 77, 6, 15, 16, 68, 85, 95, 38, 1, 
  92, 70, 5, 55, 75, 58, 60, 67, 26, 30, 107, 98, 53, 50, 4, 42, 
  29, 51, 94, 123, 115, 112, 86, 17, 74, 18, 11, 39, 35, 49, 21, 103
};

const unsigned int WGTime[128] =
{
  0, 43, 58, 17, 121, 82, 67, 104, 122, 81, 64, 107, 3, 40, 57, 18, 114, 89, 72, 99, 11, 32, 49, 26, 8, 35, 50, 25, 113, 90, 75, 96, 42, 1, 16, 59, 83, 120, 105, 66, 80, 123, 106, 65, 41, 2, 19, 56, 88, 115, 98, 73, 33, 10, 27, 48, 34, 9, 24, 51, 91, 112, 97, 74, 76, 103, 118, 93, 53, 30, 15, 36, 54, 29, 12, 39, 79, 100, 117, 94, 62, 21, 4, 47, 71, 108, 125, 86, 68, 111, 126, 85, 61, 22, 7, 44, 102, 77, 92, 119, 31, 52, 37, 14, 28, 55, 38, 13, 101, 78, 95, 116, 20, 63, 46, 5, 109, 70, 87, 124, 110, 69, 84, 127, 23, 60, 45, 6
};

const unsigned char Key[18]=
{
  127, 127, 127, 127, 127, 127, 127, 127, 
  127, 127, 127, 127, 127, 127, 127, 127, 
  127, 127
};


//WG Encryption
void wg7(volatile unsigned char *IV, volatile unsigned char *keystream)
{
  ////////////////////////////////////////////////////////////////
  //Variables for WG-7
  ////////////////////////////////////////////////////////////////
  unsigned int i, j;
  unsigned char tmp;
  unsigned char state[23];

  ////////////////////////////////////////////////////////////////
  //WG-7 Init
  ////////////////////////////////////////////////////////////////	
  // Key scheduling
  for(i=0; i<18; ++i) state[i] = Key[i];
  state[18] = IV[0] & 0x7E;
  state[19] = IV[1] & 0x7E;
  state[20] = IV[2] & 0x7E;
  state[21] = IV[3] & 0x7E;
  state[22] = ((IV[0] & 0x80)<<7) | ((IV[0] & 0x80)<<5) | ((IV[0] & 0x80)<<3) | ((IV[0] & 0x80)<<1);
  
  
  // Run WG-Perm 46 rounds
  for(i=0; i<46; ++i){
    tmp = WGPerm[state[22]] ^ state[20] ^ state[18] ^ state[15] ^ state[14] ^ state[13]^ state[12]^ state[11]^ state[10] ^ state[9] ^ state[7] ^ state[5] ^ state[1] ^ WGTime[state[0]];
    for(j=0; j<22; ++j) 
      state[j] = state[j+1];
    state[22] = tmp;
  }

  ////////////////////////////////////////////////////////////////
  //WG-7 Keystream Generation
  ////////////////////////////////////////////////////////////////	
        
  for(i=0; i<96; ++i){
    tmp = state[20] ^ state[18] ^ state[15] ^ state[14] ^ state[13]^ state[12]^ state[11]^ state[10] ^ state[9] ^ state[7] ^ state[5] ^ state[1] ^ WGTime[state[0]];
    for(int j=0; j<22; ++j) 
      state[j] = state[j+1];
    state[22] = tmp;
  
    //Output 1 bit per time
    keystream[i/8] |= (WGTrans[tmp])<<(7-(i%8));
  }
}