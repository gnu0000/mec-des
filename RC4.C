/*
 *
 * rc4.c
 * Thursday, 4/17/1997.
 *
 * The encryption algorithm used in this module was derived from 
 * 'Applied Cryptography 2nd Ed' (c) 1996 by Bruce Schneider
 * and was developed by Ron Rivest for RSA Data Security Inc.
 *
 *
 * To encrypt a small buffer, simply call Crypt
 * To encrypt a stream call InitSBox and then call CryptStream as many
 * times as needed.
 *
 * Note that the algorithm is symmetric - ie decryption ð decryption
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnuType.h>
#include <gnuArg.h>
#include <gnuMisc.h>

/***************************************************************************/
/*                                                                         */
/*                                                                         */
/*                                                                         */
/***************************************************************************/

static UCHAR cI, cJ, s[256];

void InitSBox (PSZ pszKey)
   {
   PSZ   psz = pszKey;
   UCHAR j, tmp, k[256];
   int   i;

   for (cI=cJ=i=0; i<256; i++)
      {
      s[i] =i;
      if (!*psz) psz = pszKey;
      k[i] = *psz++;
      }
   for (j=i=0; i<256; i++)
      {
      j   = (j + s[i] + k[i]);
      tmp = s[i], s[i] = s[j], s[j] = tmp;
      }
   }

PSZ CryptStream (PSZ pszOut, PSZ pszIn, int iSrcLen)
   {
   int   i;
   UCHAR tmp, t;

   for (i=0; i< iSrcLen; i++)
      {
      cI += 1;
      cJ += s[cI];
      tmp = s[cI], s[cI] = s[cJ], s[cJ] = tmp;
      t   = s[cI] + s[cJ];
      *pszOut++ = *pszIn++ ^ s[t];
      }
   return pszOut;
   }

PSZ Crypt (PSZ pszOut, PSZ pszIn, int iSrcLen, PSZ pszKey)
   {
   InitSBox (pszKey);
   return CryptStream (pszOut, pszIn, iSrcLen);
   }

#define BUFFLEN 16

/***************************************************************************/
/*                                                                         */
/*                                                                         */
/*                                                                         */
/***************************************************************************/

#define BLOCKSIZE 4096  // must be divisible by 8

CHAR szINBUFF  [BLOCKSIZE];
CHAR szOUTBUFF [BLOCKSIZE];

void Usage (void)
   {
   printf ("RC4  File Encrypt/Decript utility  v1.0   %s   %s\n", __DATE__, __TIME__);
   printf ("\n");
   printf ("USAGE:  RC4  /Key=str infile outfile\n");
   printf ("\n");
   printf ("WHERE:  /Key=str .... Encrypt/Decrypt key.\n");
   printf ("        infile ...... Input filename\n");
   printf ("        outfile ..... Output filename\n");
   printf ("\n");
   printf ("Algorithm is symmetric (encryption same as descrption).\n");
   exit (0);
   }


int main (int argc, char *argv[])
   {
   FILE *fpIn, *fpOut;
   PSZ  pszKey, pszInFile, pszOutFile;
   UINT uRead, uWrote;


   ArgBuildBlk ("? *^Debug *^Key%");

   if (ArgFillBlk (argv))
      Error ("%s", ArgGetErr ());

   if (ArgIs ("?") || ArgIs (NULL) < 2 || !ArgIs ("Key"))
      Usage ();

   pszInFile  = ArgGet (NULL,  0);
   pszOutFile = ArgGet (NULL,  1);
   pszKey     = ArgGet ("Key", 0);

   if (!(fpIn = fopen (pszInFile, "rb")))
      Error ("Cannot open input file %s", pszInFile);
   if (!(fpOut = fopen (pszOutFile, "wb")))
      Error ("Cannot open output file %s", pszOutFile);

   InitSBox (pszKey);

   while (uRead = fread (szINBUFF, 1, BLOCKSIZE, fpIn))
      {
      CryptStream (szINBUFF, szINBUFF, uRead);
      uWrote = fwrite (szINBUFF, 1, uRead, fpOut);
      if (uWrote != uRead)
         Error ("Error writing file");
      }
   fclose (fpIn);
   fclose (fpOut);
   printf ("Done.");
   return 0;
   }


