/**********************************************************************************************/
/**********************************************************************************************/
/***                           Program : Cipher                                             ***/
/***                           Class   : CSE 376 Homework 1                                 ***/
/***                           File    : cipher.h                                           ***/
/***                           Author  : Frank Pernice                                      ***/
/***                           Version : 1.0                                                ***/
/***                           Date    : 25 September 2014                                  ***/
/**********************************************************************************************/
/**********************************************************************************************/


#ifndef CIPHER_H_
#define CIPHER_H_

/*============================================================================================*/
/* Headers                                                                                    */
/*============================================================================================*/
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdlib.h>

#include "blowfish.h"

/*============================================================================================*/
/* Definitions                                                                                */
/*============================================================================================*/
#define VERSION "1.0"

/*============================================================================================*/
/* Typedefs                                                                                   */
/*============================================================================================*/
//enumerations
typedef enum { false, true } bool; //ensures c89 compatibility

//Structures
typedef struct
{
  char mode;            //e = encrypt, d = decrypt
  char* infile;         //name of infile
  char* outfile;        //name of outfile
  char* password;       //password string
} cipher_t;

typedef struct
{
  struct stat infile_stats;     //infile stat object from stat() function
  struct stat outfile_stats;    //outfile stat object from stat() function
  struct statvfs filesys_stats; //filesystem stats object from statvfs() function
  bool overwrite_outfile;       //indicates if the outfile already exists or not
  bool stdin_selected;          //indicates if stdin was chosen
  bool stdout_selected;         //indicates if stdout was chosen
}cipher_fileInfo_t;

/*============================================================================================*/
/* Function Prototypes                                                                        */
/*============================================================================================*/
// Terminal Parsing Functions
cipher_t cipher_parseArguments(int argc, char *argv[]);

// File Functions
cipher_fileInfo_t cipher_check_files(cipher_t data);

// Encryption Functions
void cipher_encrypt(cipher_t data);

#endif /* CIPHER_H_ */
