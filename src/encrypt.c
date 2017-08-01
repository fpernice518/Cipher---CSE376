/**********************************************************************************************/
/**********************************************************************************************/
/***                           Program : Cipher                                             ***/
/***                           Class   : CSE 376 Homework 1                                 ***/
/***                           File    : encrypt.c                                          ***/
/***                           Author  : Frank Pernice                                      ***/
/***                           Version : 1.0                                                ***/
/***                           Date    : 25 September 2014                                  ***/
/**********************************************************************************************/
/**********************************************************************************************/

/*============================================================================================*/
/* Headers                                                                                    */
/*============================================================================================*/
//System headers
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

//local headers
#include "blowfish.h"
#include "cipher.h"

/*============================================================================================*/
/* Function Prototypes                                                                        */
/*============================================================================================*/
static void cipher_copyBuffer(unsigned char src[], unsigned char dest[], int src_start,
                              int src_stop, int dest_start, int dest_stop);

/*============================================================================================*/
/* Encryption Functions                                                                       */
/*============================================================================================*/

/* Encrypts or decrypts data and deletes the old file, exits program upon failure
 *
 * Preconditions:  Data has been successfully parsed from command line and stored in cipher_t
 * Postconditions: Infile is encrypted or decrypted and result is saved to outfile. Infile is 
 *                 then deleted.
 *
 */
void cipher_encrypt(cipher_t data)
{
  int err;                  //error indicator
  int fd_infile;            //infile file descriptor
  int fd_outfile;           //outfile file descriptor
  int page_size;            //system page size
  int n = 0;                //internal blowfish variable
  int i;                    //loop variable

  unsigned char *infile_buf;   //infile buffer
  unsigned char *outfile_buf;  //infile buffer
  unsigned char to_bf[128];    //blowfish to buffer
  unsigned char from_bf[128];  //blowfish from buffer
  unsigned char iv[8];         //blowfish initialization vector
  unsigned char *pPswd;        //password pointer

  cipher_fileInfo_t info;   //info about files and filessystem
  BF_KEY key;               //blowfish key

  //check infiles and get system info
  info = cipher_check_files(data);

  //open infile or stdin
  if(false == info.stdin_selected)
    fd_infile = open(data.infile, O_RDONLY);
  else
    fd_infile = STDIN_FILENO;

  //open outfile or stdout
  if(false == info.stdout_selected)
  {
    if(true == info.overwrite_outfile) //if file exists, keep current permissions
      fd_outfile = open(data.outfile, O_WRONLY | O_CREAT | O_NOCTTY | O_TRUNC);
    else                               //otherwise use 666 for permissions
      fd_outfile = open(data.outfile, O_WRONLY | O_CREAT | O_NOCTTY | O_EXCL, 0666);
  }
  else
    fd_outfile = STDOUT_FILENO;

  //check for file descriptor errors
  if(-1 == fd_infile)
  {
    fprintf(stderr, "Cipher Error: (infile) %s\n", strerror(errno));
    exit(-1);
  }
  if(-1 == fd_outfile)
  {

    fprintf(stderr, "Cipher Error: (outfile) %s\n", strerror(errno));
    exit(-1);
  }

  page_size = getpagesize();       //get system page size
  infile_buf = malloc(page_size);  //allocate room for infile buffer
  outfile_buf = malloc(page_size); //allocate room for outfile buffer

  //check for allocation errors
  if(NULL == infile_buf)
  {
    fprintf(stderr, "Cipher Error: (infile) %s", strerror(errno));
    exit(-1);
  }
  if(NULL == outfile_buf)
  {
    fprintf(stderr, "Cipher Error: (outfile) %s", strerror(errno));
    exit(-1);
  }

  //blowfish initialization
  memset(iv, 0, 8);         
  pPswd = (unsigned char*)data.password;
  BF_set_key(&key, strlen(data.password), pPswd);

  //begin encryption
  do
  {
    err = read(fd_infile, infile_buf, page_size);

    if(0 > err) //check for read error
      fprintf(stderr, "Cipher Error: %s\n", strerror(errno));

    //copy data in blocks to buffer
    for(i = 0; i < page_size; i += 128)
    {
      cipher_copyBuffer(infile_buf, from_bf, i, i+128, 0, 128);
      if('e' == data.mode)
        BF_cfb64_encrypt(from_bf, to_bf, 128, &key, iv, &n, BF_ENCRYPT);
      else
        BF_cfb64_encrypt(from_bf, to_bf, 128, &key, iv, &n, BF_DECRYPT);

      cipher_copyBuffer(to_bf, outfile_buf, 0, 128, i, i+128);
    }
    //write block of size page_size to outfile
    write(fd_outfile,outfile_buf, err);

  }while(err == page_size);
  
  //close infile, report errors
  err = close(fd_infile);
  if(0 != err)
    fprintf(stderr, "Cipher Error: (infile) %s\n", strerror(errno));
  
  //close outfile, report errors
  err = close(fd_outfile);
  if(0 != err)
    fprintf(stderr, "Cipher Error: (outfile) %s\n", strerror(errno));
  
  //delete infile, report errors
  err = remove(data.infile);
  if(0 != err && false == info.stdin_selected)
    fprintf(stderr, "Cipher Error: (infile) %s\n", strerror(errno));
  
  //free pointers
  free(infile_buf);
  free(outfile_buf);
  
  //inform user of completeness
  printf("done!\n");
}

/* Copies one character buffer to another between provided start and stop indicies.
 *
 * Preconditions:  src and dest buffers have been properly allocated
 * Postconditions: src has been copied to dest between provided indicies.
 *
 */
static void cipher_copyBuffer(unsigned char src[], unsigned char dest[], int src_start, int src_stop, int dest_start, int dest_stop)
{
  int src_index, dest_index;
  long src_len, dest_len;

  src_len = (long)src_stop - (long)src_start;
  dest_len = (long)dest_stop - (long) dest_start;

  //ensure that parameters are correct
  if((dest_len != src_len) || (0 > dest_len) || (0 > src_len) || NULL == src || NULL == dest)
  {
    fprintf(stderr, "Cipher Error: buffer copy error");
    exit(-1);
  }

  for(src_index = src_start, dest_index = dest_start; src_index < src_stop; ++src_index, ++dest_index)
  {
    dest[dest_index] = src[src_index];
  }
  return;
}

