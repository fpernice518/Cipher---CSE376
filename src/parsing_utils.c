/**********************************************************************************************/
/**********************************************************************************************/
/***                           Program : Cipher                                             ***/
/***                           Class   : CSE 376 Homework 1                                 ***/
/***                           File    : parsing_utils.c                                    ***/
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
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

//Local Headers
#include "cipher.h"

/*============================================================================================*/
/* Function Prototypes                                                                        */
/*============================================================================================*/
static void ciper_printHelpMenu();
static void cipher_optionCountChecker(unsigned count, char* opt);

/*============================================================================================*/
/* Terminal Parsing Functions                                                                 */
/*============================================================================================*/

/* Parses arguments from command line and exits upon failure, stores retrieved data into
 * a cipher_t structure
 *
 * Preconditions:  none
 * Postconditions: Data is parsed from command line and stored in the returned structure.
 *
 */
cipher_t cipher_parseArguments(int argc, char *argv[])
{
 //option count variables
  unsigned d_cnt   = 0;
  unsigned e_cnt   = 0;
  unsigned h_cnt   = 0;
  unsigned p_cnt   = 0;
  unsigned v_cnt   = 0;
  unsigned s_cnt   = 0;
  unsigned arg_cnt = 0;

  //Misc variables
  char opt;                //current option
  char* p_arg = "";        //temporary pointer for password
  char* safe_pass;         //pointer for safe password
  cipher_t cipher_data;    //stores retrieved data
  char* pass_msg = "";     //stores getpass() message for first pass
  char* s_pass_msg;        //stores getpass() message for safe pass
  
  //initialize structure to keep gcc happy
  cipher_data.mode = 0;

  //scan for options
  while (-1 != (opt = getopt(argc, argv, "deh:p:sv")))
  {
    switch(opt)
    {
      case 'd':             //decrypt
        cipher_data.mode = opt;
        ++d_cnt;
        break;
 
      case 'e':             //encrypt
        cipher_data.mode = opt;
        ++e_cnt;
        break;

      case 'h':             //help
        ++h_cnt;
        break;
 
      case 'p':             //password
        p_arg = strdup(optarg);
        ++p_cnt;
        break;

      case 's':
        ++s_cnt;
        break;
 
      case 'v':             //version
        ++v_cnt;
        break;
 
    default:                //any unrecognized commands will result in the default case
        ciper_printHelpMenu();
        fprintf(stderr, "Cipher Error: unrecognized command %c\n", opt);
        exit(-1);
    }
    ++arg_cnt;
  }
    
  //check that no option is repeated
  cipher_optionCountChecker(d_cnt, "-d");
  cipher_optionCountChecker(e_cnt, "-e");
  cipher_optionCountChecker(h_cnt, "-h");
  cipher_optionCountChecker(p_cnt, "-p");
  cipher_optionCountChecker(s_cnt, "-s");
  cipher_optionCountChecker(v_cnt, "-v");
  
  //print version
  if(1 == v_cnt)
  {
    if(1 != arg_cnt) //ensure that only the -v option was used
    { 
      fprintf(stderr, "Cipher Error: too many arguments for -v\n\n\n");
      ciper_printHelpMenu();
      exit(-1);
    }
    else if(2 != argc)
    {
      fprintf(stderr, "Cipher Error: -v option does not take any file names.\n\n\n");
      ciper_printHelpMenu();
      exit(-1);
    }

    printf("Cipher Error: Version = %s\n", VERSION);
    exit(0);
  }
  
  //print help menu
  if(1 == h_cnt)
  {
    if(1 != arg_cnt) //ensure that only the -h option was used
    { 
      fprintf(stderr, "Cipher Error: too many arguments for -h\n\n\n");
      ciper_printHelpMenu();
      exit(-1);
    }
    else if(2 != argc)
    {
      fprintf(stderr,  "Cipher Error: -h option does not take any file names.\n\n\n");
      ciper_printHelpMenu();
      exit(-1);
    }

    ciper_printHelpMenu();
    fprintf(stderr, "Cipher Error: Help menu requested\n"); //as specified in HW description
    exit(-1);
  }

  //Ensure that -d and -e are used exclusively, one of them is used, and they are only once
  if(1 != (d_cnt + e_cnt ))
  {
    fprintf(stderr, "Cipher Error:  Please specify -d (decryption) or -e(encryption), but not both.\n\n\n");
    ciper_printHelpMenu();                    
    exit(-1);
  }
  else if(2 != (argc - optind)) //ensure we have an infile and outfile
  {
    fprintf(stderr, "Cipher Error: Please specify only one infile and only one outfile (no more, no less).\n\n\n");
    ciper_printHelpMenu();
    exit(-1);
  }
  
  //take care of password stuff
  if(0 == p_cnt)
  {
  	pass_msg = malloc(sizeof(pass_msg) * 256);

    if(NULL == pass_msg)
    {
      fprintf(stderr, "Cipher Error: %s", strerror(errno));
      exit(-1);
    }

    sprintf(pass_msg, "Cipher: Enter a password (8 to %d characters) ", INT_MAX);

    //get a password of at least 8 characters wide
    cipher_data.password = strdup(getpass(pass_msg));

    while(strlen(cipher_data.password) < 8 || strlen(cipher_data.password)> INT_MAX)
    {
      fprintf(stderr, "Please enter a password of length 8 to %d characters\n", INT_MAX);
      cipher_data.password = strdup(getpass(pass_msg));
    }

   if(NULL == cipher_data.password) //did getpass return with error?
   {
     perror("Cipher Error");        //if so, print an error
     ciper_printHelpMenu();
     free(pass_msg);                //free data
     exit(-1);                      //and exit
   }

   free(pass_msg);
  }
  else
   cipher_data.password = p_arg;

  if(1 == s_cnt)
  {
  	s_pass_msg = malloc(sizeof(s_pass_msg) * 256);

  	if(NULL == pass_msg)
    {
      fprintf(stderr, "Cipher Error: %s", strerror(errno));
      exit(-1);
    }

  	sprintf(s_pass_msg, "Cipher: retype password to confirm ");

  	safe_pass = strdup(getpass(s_pass_msg));;

  	if(0 != strcmp(safe_pass, cipher_data.password))
  	{
  		fprintf(stderr, "Cipher Error: Passwords do not match\n");
  		free(s_pass_msg);
  		free(safe_pass);
  		exit(-1);
  	}

    free(safe_pass);
  	free(s_pass_msg);
  }
  
  cipher_data.infile = argv[optind];
  cipher_data.outfile = argv[optind+1];

  return cipher_data;
}


/* Prints the help menu
 *
 * Preconditions:  none
 * Postconditions: none
 *
 */
static void ciper_printHelpMenu()
{
  printf( "=====================================================================================\n"
          "\nUsage is as follows:\n      cipher [-devh] [-p PASSWD] infile outfile\n"
          "\nOPTIONS:\n"
          "-d = decrypt infile and save to outfile (should not be used with -e).\n"
          "-e = encrypt infile and save to outfile (should not be used with -d).\n"
          "-h = display this help menu\n"
          "-p = used to specify a password; MUST be immediately followed by the password!\n"
          "-v = used to print the version of this program\n\n"
          "infile = the file to be encrypted/decrypted\n"
          "outfile = the resulting encrypted/decrypted file\n\n"
          "=====================================================================================\n");
}

/* Ensures that the passed option was not used mor ethan once
 *
 * Preconditions:  none
 * Postconditions: none
 *                 
 *
 */
static void cipher_optionCountChecker(unsigned count, char* opt)
{
  if(1 < count)
  {
    fprintf(stderr, "Cipher Error: option %s cannot be used more than once", opt);
    exit(-1);    
  }
}
