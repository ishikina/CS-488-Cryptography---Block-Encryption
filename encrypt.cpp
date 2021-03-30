#include "program1.h"

//Encryption process
void encrypt(string plaintext_file, string key_file, string ciphertext_file)
{
	//Obtain key	
	string key_string = file_to_string(key_file);
	istringstream convert(key_string);
	uint64_t key;
	convert >> hex >> key;
	cout << "\nKEY: " << hex << key << endl;

	//Create subkeys
	string key_binary = hex_to_binary(key_string);
 	create_subkeys(key_binary);
	subkey_convert();
	cout << "\nSUB KEYS: " << endl;
	int flag = 1;	
	display_subkeys(flag);

	//Process plaintext
	string plaintext_string = file_to_string(plaintext_file);
  input_to_hex(plaintext_string);
	cout << "\nPLAINTEXT: " << plaintext_string << endl;
	
	//Encrypt
	for(int i = 0; input[i]; ++i)
		cipherblocks[i].des(input[i], key, flag);	

	//Print to file
	psu_crypt_to_file(cipherblocks, ciphertext_file, flag);
	cout << "\nCIPHERTEXT: ";
	for(int i = 0; cipherblocks[i + 1].text; ++i)
		cout << hex << cipherblocks[i].text;
	cout << endl; 
}

//Converting input file string to uint64_t in hex
void input_to_hex(string plaintext)
{
	int length = plaintext.length();	
	int remainder = length % 8;
	int loop = 0;
	
	for(int i = 0; i < 8 - remainder; ++i)
		plaintext[length + i] = '\0';

	if(remainder)
		loop = (length / 8) + 1;
	else
		loop = length / 8;
	
	for(int i = 0; i < loop; ++i)
	{
		uint32_t high = (plaintext[i * 8] << 24) | (plaintext[(i * 8) + 1] << 16) | (plaintext[(i * 8) + 2] << 8) | (plaintext[(i * 8) + 3]);
		uint32_t low = (plaintext[(i * 8) + 4] << 24) | (plaintext[(i * 8) + 5] << 16) | (plaintext[(i * 8) + 6] << 8) | (plaintext[(i * 8) + 7]);
		input[i] = ((uint64_t)high << 32) | (low);
	}
}


