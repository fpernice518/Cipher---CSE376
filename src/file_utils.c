/**********************************************************************************************/
/**********************************************************************************************/
/***                           Program : Cipher                                             ***/
/***                           Class   : CSE 376 Homework 1                                 ***/
/***                           File    : file_utils.c                                       ***/
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
//#include <fcntl.h>
// /#include <limits.h>
#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
//#include <sys/stat.h>
//include <sys/statvfs.h>
//#include <sys/types.h>
#include <unistd.h>

//Local Headers
#include "blowfish.h"
#include "cipher.h"

/*============================================================================================*/
/* File Functions                                                                             */
/*============================================================================================*/


/*
 * Checks the validity of the provided files and handles stdio if necessary. Exits program on 
 * failure
 *
 * Preconditions:  The command line info has been parsed and stored in the cipher_t structure
 * Postconditions: Informational flags are set and more detailed information is stored
 * in the returned cipher_fileInfo_t structure.
 *
 */
cipher_fileInfo_t cipher_check_files(cipher_t data)
{
  int err = 0;
  cipher_fileInfo_t info;
  bool stdin_selected = false;
  bool stdout_selected = false;
  bool outfile_exists = false;

  //read infile stats, determine if user chose stdin
  if(0 == strcmp(data.infile, "-"))
  {
    stdin_selected = true;
    err = fstat(STDIN_FILENO, &info.infile_stats);
  }
  else
  {
    err = stat(data.infile, &info.infile_stats);
  }
  
  //check that infile exists or for other errors from stat()
  if(0 != err && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: %s (%s)\n", strerror(errno), data.infile);
    exit(-1);
  }

  //read outfile stats, determine if user chose stdout
  if(0 == strcmp(data.outfile, "-"))
  {
    stdout_selected = true;
    err = fstat(STDIN_FILENO, &info.outfile_stats);
  }
  else
  {
    err = stat(data.outfile, &info.outfile_stats);
  }
  
  //check that outfile exists or for other errors from stat()
  if(0 == err && false == stdout_selected)
    outfile_exists = true;
  
  //get info about file system and report errors
  //should check if infile path is too long
  if(0 != statvfs(data.infile, &info.filesys_stats) && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: %s\n", strerror(errno));
    exit(-1);
  }

  //ensure that infile != outfile
  if(0 == strcmp(data.infile, data.outfile) && false == stdout_selected && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: Input and output files are identical\n");
    exit(-1);
  }

  //check if infile is a directory
  if(0 != S_ISDIR(info.infile_stats.st_mode))
  {
    fprintf(stderr, "Cipher Error: %s is a directory\n", data.infile);
    exit(-1);
  }

  //check if outfile is a directory
  if(0 != S_ISDIR(info.outfile_stats.st_mode) && true == outfile_exists)
  {
    fprintf(stderr, "Cipher Error: %s is a directory\n", data.outfile);
    exit(-1);
  }
  
  //check if infile is a character device
  if(0 != S_ISCHR(info.infile_stats.st_mode) && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: %s is a character device\n", data.infile);
    exit(-1);
  }

  //check if outfile is a character device
  if(0 != S_ISCHR(info.outfile_stats.st_mode) && false == stdout_selected && true == outfile_exists)
  {
    fprintf(stderr, "Cipher Error: %s is a character device\n", data.outfile);
    exit(-1);
  }

  //check if infile is a block
  if(0 != S_ISBLK(info.infile_stats.st_mode))
  {
    fprintf(stderr, "Cipher Error: %s is a block\n", data.infile);
    exit(-1);
  }

  //check if outfile is a block
  if(0 != S_ISBLK(info.outfile_stats.st_mode) && true == outfile_exists)
  {
    fprintf(stderr, "Cipher Error: %s is a block\n", data.outfile);
    exit(-1);
  }

  //check if infile is a symbolic link
  if(0 != S_ISLNK(info.infile_stats.st_mode))
  {
    fprintf(stderr, "Cipher Error: %s symbolic links are not supported in version %s\n", data.infile, VERSION);
    exit(-1);
  }

  //check if outfile is a symbolic link
  if(0 != S_ISLNK(info.outfile_stats.st_mode) && true == outfile_exists)
  {
    fprintf(stderr, "Cipher Error: %s symbolic links are not supported in version %s\n", data.outfile, VERSION);
    exit(-1);
  }

  //check if infile is a FIFO
  if(0 != S_ISFIFO(info.infile_stats.st_mode) && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: %s is a FIFO\n", data.infile);
    exit(-1);
  }

  //check if outfile is a FIFO
  if((0 != S_ISFIFO(info.outfile_stats.st_mode)) && (true == outfile_exists) && (false == stdout_selected))
  {
    fprintf(stderr, "Cipher Error: %s is a FIFO\n", data.outfile);
    exit(-1);
  }

  //check if infile is a Socket
  if(0 != S_ISSOCK(info.infile_stats.st_mode))
  {
    fprintf(stderr, "Cipher Error: %s is a Socket\n", data.infile);
    exit(-1);
  }

  //check if outfile is a FIFO
  if(0 != S_ISFIFO(info.outfile_stats.st_mode) && true == outfile_exists)
  {
    fprintf(stderr, "Cipher Error: %s is a Socket\n", data.outfile);
    exit(-1);
  }

  /* check if infile is a regular file
   * Note that this "should" be enough; however, in order to provide
   * detailed messages as required, we must check the other flags
   * in st_mode as well (as done above).
   */
  if(0 == S_ISREG(info.infile_stats.st_mode) && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: %s is not a regular file\n", data.infile);
    exit(-1);
  }

  //check if outfile is a regular file
  if((0 == S_ISREG(info.outfile_stats.st_mode)) && (false == stdout_selected) && (true == outfile_exists))
  {
    fprintf(stderr, "Cipher Error: %s is not a regular file\n", data.outfile);
    exit(-1);
  }
  
  //check that we have read permissions for infile
  if(0 == (info.infile_stats.st_mode & S_IRUSR))
  {
    fprintf(stderr, "Cipher Error: insufficient read privledges for infile (%s)\n", data.infile);
    exit(-1);
  }
  
  //check that we have write permissions for outfile
  if(0 == (info.outfile_stats.st_mode & S_IWUSR) && true == outfile_exists)
  {
    fprintf(stderr, "Cipher Error: insufficient write privledges for outfile (%s)\n", data.outfile);
    exit(-1);
  }

  //double check that the infile just in case
  if(FILENAME_MAX < strlen(data.infile))
  {
    fprintf(stderr, "Cipher Error: infile name is too long.\n");
    exit(-1);
  }

  //ensure that outfile name isn't too long
  if(FILENAME_MAX < strlen(data.outfile))
  {
    fprintf(stderr, "Cipher Error: outfile name is too long.\n");
    exit(-1);
  }

  //ensure sufficient disk space
  if((info.filesys_stats.f_bsize * info.filesys_stats.f_bfree <= info.infile_stats.st_size) && false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: insufficient space to perform encryption\n");
    exit(-1);
  }

  if(0 == info.infile_stats.st_size&& false == stdin_selected)
  {
    fprintf(stderr, "Cipher Error: Infile is empty\n");
    exit(-1);
  }

  if(false == outfile_exists && false == stdout_selected)
    fprintf(stdout, "Cipher: generating outfile %s\n", data.outfile);
  else if(true == stdout_selected)
    fprintf(stdout, "Cipher: writing to stdout\n");
  else
    fprintf(stdout, "Cipher: overwriting outfile %s\n", data.outfile);

  //Set informational flags
  info.stdin_selected = stdin_selected;
  info.stdout_selected = stdout_selected;
  info.overwrite_outfile = outfile_exists;

  //return information
  return info;
}

