:#include "program1.h"

//Decryption process
void decrypt(string ciphertext_file, string key_file, string plaintext_file)
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
	int flag = 0;	
	display_subkeys(flag);

	//Process ciphertext
	string ciphertext_string = file_to_string(ciphertext_file);
	convert_hex(ciphertext_string);
	cout << "\nCIPHERTEXT: " << ciphertext_string << endl;

	//Decrypt				
	for(int i = 0; input[i]; ++i)
		cipherblocks[i].des(input[i], key, flag);	
	
	//Print to file
	psu_crypt_to_file(cipherblocks, plaintext_file, flag);
	cout << "\nPLAINTEXT: ";
	for(int i = 0; cipherblocks[i + 1].text; ++i)
	{
			bitset<64> hex1(cipherblocks[i].text);	
			stringstream hex2;
			hex2 << hex << hex1.to_ulong();	
			string hex3 = hex2.str();	
			string ascii;	
			for(int i = 0; i < hex3.length(); i += 2)
			{
				string part = hex3.substr(i, 2);
				char ch = stoul(part, nullptr, 16);
				ascii +=ch;
			}
			cout << ascii;	
	}
	cout << endl;
}

//Convert hex input to uint64_t
void convert_hex(string ciphertext)
{
	int loop = ciphertext.length() / 16;
	for(int i = 0; i < loop; ++i)
	{
		string concat = ciphertext.substr(i * 16, (i * 16) + 16);
		istringstream convert(concat);
		convert >> hex >> input[i];
	}
}
