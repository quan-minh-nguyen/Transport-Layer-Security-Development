//Header Files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

//Function Prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

/*************************************************************
						M A I N
**************************************************************/
int main (int argc, char* argv[])
{
    /***********D-Schnorr Key Generation*************/

    //Reading message and seed from files
    int messageLen;
    unsigned char* message = Read_File(argv[1], &messageLen);
    int seedLen;
    unsigned char* seed = Read_File(argv[2], &seedLen);

    //Hash the seed to get private key "y"
    unsigned char y[SHA256_DIGEST_LENGTH];
    SHA256(seed, seedLen, y);

    //Obtaining public key "Y = y * G"
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp192k1);
    //EC_POINT* G = EC_GROUP_get0_generator(group);
    
    char hex_y[64];
    Convert_to_Hex(hex_y, y, SHA256_DIGEST_LENGTH);
    
    BN_CTX *bn_ctx;
    bn_ctx = BN_CTX_new();
    BIGNUM* bignum_y = NULL;
    BN_hex2bn(&bignum_y, hex_y);

    EC_POINT* Y = EC_POINT_new(group);
    EC_POINT_mul(group, Y, bignum_y, NULL, NULL, bn_ctx);
    point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
    char* hex_Y = EC_POINT_point2hex(group, Y, form, bn_ctx);

    //Writing the hex versions of the key pair to files
    Write_File("SK_Hex.txt", hex_y);
    Write_File("PK_Hex.txt", hex_Y);


    /***********D-Schnorr Signature Generation*************/

    //Concatenate message and private key
    int m_y_concat_len = messageLen+SHA256_DIGEST_LENGTH;
    unsigned char m_y_concat[m_y_concat_len];
    memcpy(m_y_concat, message, messageLen);
    memcpy(m_y_concat + messageLen, y, SHA256_DIGEST_LENGTH);

    unsigned char r[SHA256_DIGEST_LENGTH];
    SHA256(m_y_concat, m_y_concat_len, r);

    //Performing scalar multiplcation to get R
    char hex_r[SHA256_DIGEST_LENGTH*2];
    Convert_to_Hex(hex_r, r, SHA256_DIGEST_LENGTH);

    BIGNUM* bignum_r = NULL;
    BN_hex2bn(&bignum_r, hex_r);

    EC_POINT* R = EC_POINT_new(group);
    EC_POINT_mul(group, R, bignum_r, NULL, NULL, bn_ctx);
    char* hex_R = EC_POINT_point2hex(group, R, form, bn_ctx);

    //Computing s
    //Getting unsigned char R
    unsigned char* uchar_R = NULL;
    int uchar_R_len = EC_POINT_point2buf(group, R, form, &uchar_R, bn_ctx);

    //Concatenating m and R
    int m_R_concat_len = messageLen+uchar_R_len;
    unsigned char m_R_concat[m_R_concat_len];
    memcpy(m_R_concat, message, messageLen);
    memcpy(m_R_concat + messageLen, uchar_R, uchar_R_len);

    //Getting the order
    BIGNUM* q = BN_new();
    EC_GROUP_get_order(group, q, bn_ctx);

    //Hashing m_R_concat, then converting to hex so that it can be converted to BIGNUM
    unsigned char hash_mR[SHA256_DIGEST_LENGTH];
    SHA256(m_R_concat, m_R_concat_len, hash_mR);
    char hex_hash_mR[SHA256_DIGEST_LENGTH*2];
    Convert_to_Hex(hex_hash_mR, hash_mR, SHA256_DIGEST_LENGTH);
    BIGNUM* bignum_hash_mR = NULL;
    BN_hex2bn(&bignum_hash_mR, hex_hash_mR);

    //Performing modular multiplication
    BIGNUM* y_hash_mod = BN_new();
    BN_mod_mul(y_hash_mod, bignum_y, bignum_hash_mR, q, bn_ctx);

    //Performing modular subtraction
    BIGNUM* s = BN_new();
    BN_mod_sub(s, bignum_r, y_hash_mod, q, bn_ctx);
    char* hex_s = BN_bn2hex(s);

    //Writing hex versions of R and s to files
    Write_File("R_Hex.txt", hex_R);
    Write_File("s_Hex.txt", hex_s);


    EC_POINT_free(Y);
    EC_POINT_free(R);
    BN_CTX_free(bn_ctx);
    return 0;
}

/*************************************************************
					F u n c t i o n s
**************************************************************/

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[]){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}
/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

/*============================
        Convert to Hex 
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}
//__________________________________________________________________________________________________________________________