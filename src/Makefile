#use GCC
CC = gcc

#use flags
CFLAGS = -g -O2 -Wall -Werror

#my stuff
all: cipher

cipher: cipher.c cipher.h bf_enc.o bf_cfb64.o bf_skey.o file_utils.o parsing_utils.o encrypt.o
	    @$(CC) $(CFLAGS) bf_enc.o bf_cfb64.o bf_skey.o file_utils.o parsing_utils.o encrypt.o cipher.c -o cipher

file_utils.o: cipher.h file_utils.c
	      @$(CC) $(CFLAGS) -c file_utils.c -o file_utils.o

parsing_utils.o: cipher.h parsing_utils.c
	         @$(CC) $(CFLAGS) -c parsing_utils.c -o parsing_utils.o

encrypt.o: cipher.h encrypt.c
	   @$(CC) $(CFLAGS) -c encrypt.c -o encrypt.o



#blowfish stuff
bf_enc.o: bf_locl.h blowfish.h bf_enc.c
	      @$(CC) $(CFLAGS) -c bf_enc.c -o bf_enc.o

bf_cfb64.o: bf_locl.h blowfish.h bf_cfb64.c
	        @$(CC) $(CFLAGS) -c bf_cfb64.c -o bf_cfb64.o

bf_skey.o: bf_pi.h bf_locl.h blowfish.h bf_skey.c
	       @$(CC) $(CFLAGS) -c bf_skey.c -o bf_skey.o

#clean
clean:
	   @rm cipher
	   @rm *o
