#include "program1.h"

int main(int argc, char *argv[])
{
	//Encryption
	if(strcmp(argv[1],"-e") == 0)
  {
   	cout << "ENCRYPTING: " << argv[2] << endl;
		encrypt(argv[2], argv[3], argv[4]);
	}

	//Decryption
  if(strcmp(argv[1],"-d") == 0)
  {
    cout << "DECRYPTING: " << argv[2] << endl;
		decrypt(argv[2], argv[3], argv[4]);
  }
	
	return 0;
}

