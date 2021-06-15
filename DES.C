/*
 *
 * des.c
 * Monday, 12/8/1997.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <GnuType.h>
#include <GnuArg.h>
#include <GnuDes.h>
#include <GnuMisc.h>

#define BLOCKSIZE 4096  // must be divisible by 8

CHAR szINBUFF  [BLOCKSIZE];
CHAR szOUTBUFF [BLOCKSIZE];


void Usage (void)
   {
   printf ("DES  File Encrypt/Decript utility  v1.0   %s   %s\n", __DATE__, __TIME__);
   printf ("\n");
   printf ("USAGE:  DES  [/Decrypt] /Key=str infile outfile\n");
   printf ("\n");
   printf ("WHERE:  /Decrypt .... Decrypt file.  Default is Encrypt.\n");
   printf ("        /Key=str .... Encrypt/Decrypt key.\n");
   printf ("        infile ...... Input filename\n");
   printf ("        outfile ..... Output filename\n");
   exit (0);
   }


int main (int argc, char *argv[])
   {
   FILE *fpIn, *fpOut;
   PSZ  pszKey, pszInFile, pszOutFile;
   UINT uSrcLen, uDestLen, uWrote, uKeyLen;
   BOOL bEncrypt, bDebug;

   ArgBuildBlk ("? *^Debug *^Encrypt *^Decrypt *^Key%");

   if (ArgFillBlk (argv))
      Error ("%s", ArgGetErr ());

   if (ArgIs ("?") || ArgIs (NULL) < 2 || !ArgIs ("Key"))
      Usage ();

   pszInFile  = ArgGet (NULL,  0);
   pszOutFile = ArgGet (NULL,  1);
   bEncrypt   = !ArgIs ("Decrypt");
   bDebug     = ArgIs ("Debug");

   pszKey     = ArgGet ("Key", 0);
   uKeyLen    = strlen (pszKey);

   if (!(fpIn = fopen (pszInFile, "rb")))
      Error ("Cannot open input file %s", pszInFile);
   if (!(fpOut = fopen (pszOutFile, "wb")))
      Error ("Cannot open output file %s", pszOutFile);

   while (uSrcLen = fread (szINBUFF, 1, BLOCKSIZE, fpIn))
      {
      DesBuff (szOUTBUFF, szINBUFF, uSrcLen, pszKey, uKeyLen, bEncrypt);

      uDestLen = uSrcLen;
      if (bEncrypt)
         uDestLen += (uSrcLen % 8 ? 8 - uSrcLen % 8 : 0);

      uWrote = fwrite (szOUTBUFF, 1, uDestLen, fpOut);
      if (uWrote != uDestLen)
         Error ("Error writing file");
      printf (".");
      }
   fclose (fpIn);
   fclose (fpOut);
   printf ("Done.");
   return 0;
   }

