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
    //Read the message from file
    int messageLen;
    unsigned char* message = Read_File(argv[1], &messageLen);

    //Read the public key from the file and convert it to EC_POINT
    int hex_Y_len;
    char* hex_Y = Read_File(argv[2], &hex_Y_len);
    
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp192k1);
    BN_CTX *bn_ctx;
    bn_ctx = BN_CTX_new();

    EC_POINT* Y = EC_POINT_new(group);
    EC_POINT_hex2point(group, hex_Y, Y, bn_ctx);

    //Getting signature and converting
    int hex_R_len;
    char* hex_R = Read_File(argv[3], &hex_R_len);
    int hex_s_len;
    char* hex_s = Read_File(argv[4], &hex_s_len);

    EC_POINT* R = EC_POINT_new(group);
    EC_POINT_hex2point(group, hex_R, R, bn_ctx);

    BIGNUM* s = NULL;
    BN_hex2bn(&s, hex_s);

    //Computing right part of verification formula
    //Getting unsigned char R
    point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
    unsigned char* uchar_R = NULL;
    int uchar_R_len = EC_POINT_point2buf(group, R, form, &uchar_R, bn_ctx);

    //Concatenating m and R
    int m_R_concat_len = messageLen+uchar_R_len;
    unsigned char m_R_concat[m_R_concat_len];
    memcpy(m_R_concat, message, messageLen);
    memcpy(m_R_concat + messageLen, uchar_R, uchar_R_len);

    //Hashing m_R_concat, then converting to hex so that it can be converted to BIGNUM
    unsigned char hash_mR[SHA256_DIGEST_LENGTH];
    SHA256(m_R_concat, m_R_concat_len, hash_mR);
    char hex_hash_mR[SHA256_DIGEST_LENGTH*2];
    Convert_to_Hex(hex_hash_mR, hash_mR, SHA256_DIGEST_LENGTH);
    BIGNUM* bignum_hash_mR = NULL;
    BN_hex2bn(&bignum_hash_mR, hex_hash_mR);

    //Multiplying it all together
    EC_POINT* signatureVerify = EC_POINT_new(group);

    EC_POINT_mul(group, signatureVerify, s, Y, bignum_hash_mR, bn_ctx);
    char* sig = EC_POINT_point2hex(group, signatureVerify, form, bn_ctx);
    
    //Performing comparison and writing if verification is successful
    int verify = EC_POINT_cmp(group, R, signatureVerify, bn_ctx);
    printf("verify: %d\n", verify);
    if(verify == -1){
        printf("Verification error\n");
        Write_File("Verification_Result.txt", "Verification Failed on Bob Side");
    }
    else if(verify == 1){
        printf("Verification failed\n");
        Write_File("Verification_Result.txt", "Verification Failed on Bob Side");       
    }
    else if(verify == 0){
        printf("Verification success\n");
        Write_File("Verification_Result.txt", "Successful Verification on Bob Side"); 
    }


    EC_POINT_free(Y);
    EC_POINT_free(R);
    EC_POINT_free(signatureVerify);
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