#include <iostream>
#include "sodium.h"
#include <string>
#include <fstream>

#define CHUNK_SIZE 4096

using namespace std;



int create_key(const char* name);
int create_public_private_keys(const char* name);


int read_file(const char* name, unsigned char* dir, unsigned int size);
unsigned char* read_file(const char* name, long* size);
int save_file(unsigned char* text, const char* name, unsigned int size);


static int encrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

static int decrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

int verify_sign(const char* target, const char* source,
    unsigned char pk[crypto_sign_PUBLICKEYBYTES]);

int sign(const char* target, const char* source,
    unsigned char sk[crypto_sign_SECRETKEYBYTES]);

int test();
int terminal();

int main()
{
    if (sodium_init() < 0)
        return 1;
    terminal();

    return 0;
};

int terminal() {
    /*
    This function works like a console interactive menu that is writen in spanish.
    */

    //Declaration of variables
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    string name_key = "";
    string name_pk = "";
    string name_sk = "";

    string tmp = "";
    string tmp2 = "";

    int status = 0;
    int inStatus = 0;

    //Interactive menu
    while (status != 7) {
        cout << "Llave encryptado: " << name_key << endl
            << "Llave publica: " << name_pk << endl
            << "Llave privada: " << name_sk << endl << endl;

        cout << "Ingresa la accion a realizar:" << endl <<
            "\t1. Generar llaves" << endl <<
            "\t2. Leer llaves" << endl <<
            "\t3. Cifrar archivo" << endl <<
            "\t4. Descifrar archivo" << endl <<
            "\t5. Firmar archivo" << endl <<
            "\t6. Verificar firma" << endl <<
            "\t7. Cerrar programa" << endl;

        //Input for action to do.
        std::cin >> status;
        system("cls");
        switch (status) {
            //Case 1| Generation of keys
        case 1:
            //Selects the kind of key to create.
            cout << "Ingresa la acción a realizar:" << endl <<
                "\t1. Generar llave para encriptar" << endl <<
                "\t2. Generar par de llaves de firma" << endl;
            std::cin >> inStatus;
            //Creates key for encrypting usign chacha20 poly 1305
            if (inStatus == 1) {
                cout << "Ingresa el nombre para el archivo" << endl;
                std::cin >> tmp;
                tmp += ".key";
                if (create_key(tmp.c_str()))
                    cout << "No fue posible guardar la llave" << endl;
                else
                    cout << "El archivo se guardo como " + tmp << endl;
            }
            //Creates keys for sign
            else if (inStatus == 2) {
                cout << "Ingresa el nombre para el par de archivos" << endl;
                std::cin >> tmp;
                if (create_public_private_keys(tmp.c_str()))
                    cout << "No fue posible guardar las llaves" << endl;
                else
                    cout << "Las llaves se guardaron como:" << endl << tmp + ".pk" << endl << tmp + ".sk" << endl;
            }
            else cout << "Instruccion no determinada" << endl;
            break;
        //Case 2 | Read keys
        case 2:
            //Selects key to read
            cout << "Ingresa la accion a realizar:" << endl <<
                "\t1. Leer llave para encriptar" << endl <<
                "\t2. Leer llave publica" << endl <<
                "\t3. Leer llave privada" << endl;
            std::cin >> inStatus;
            
            if (inStatus >= 1 && inStatus <= 3) {
                cout << "Ingresa el nombre del archivo" << endl;
                std::cin >> tmp;
            }
            //Read key for chacha 20 poly 1305 encyption
            if (inStatus == 1) {
                if (read_file(tmp.c_str(), key, crypto_secretstream_xchacha20poly1305_KEYBYTES))
                    cout << "No fue posible leer la llave" << endl;
                else {
                    name_key = tmp;
                    cout << "Se leyo correctamente la llave" << endl;
                }
                break;

            }
            //Reads public key for signed verification
            if (inStatus == 2) {
                if (read_file(tmp.c_str(), pk, crypto_sign_PUBLICKEYBYTES))
                    cout << "No fue posible leer la llave publica" << endl;
                else {
                    name_pk = tmp;
                    cout << "Se leyo correctamente la llave publica" << endl;
                }
                break;
            }
            //Reads private key for signing
            if (inStatus == 3) {
                if (read_file(tmp.c_str(), sk, crypto_sign_SECRETKEYBYTES))
                    cout << "No fue posible leer la llave privada" << endl;
                else {
                    name_sk = tmp;
                    cout << "Se leyo correctamente la llave privada" << endl;
                }
                break;
            }
            cout << "Instruccion no determinada" << endl;
            break;
        //case 3 | Encrypt File
        case 3:
            cout << "Ingresa el archivo a cifrar" << endl;
            cin >> tmp;
            cout << "Ingresa el nombre a guardar" << endl;
            cin >> tmp2;
            if (encrypt(tmp2.c_str(), tmp.c_str(), key)) {
                cout << "No fue posible encriptar el archivo" << endl;
                break;
            }
            cout << "Se encripto correctamente el archivo" << endl;
            break;

        //case 4 | Decrypt File
        case 4:
            cout << "Ingresa el archivo a descifrar" << endl;
            cin >> tmp;
            cout << "Ingresa el nombre a guardar" << endl;
            cin >> tmp2;
            if (decrypt(tmp2.c_str(), tmp.c_str(), key)) {
                cout << "No fue posible descifrar el archivo" << endl;
                break;
            }
            cout << "Se descrifro correctamente el archivo" << endl;
            break;

        //case 5 | Sign File
        case 5:
            cout << "Ingresa el archivo a firmar" << endl;
            cin >> tmp;
            cout << "Ingresa el nombre a guardar" << endl;
            cin >> tmp2;
            if (sign(tmp2.c_str(), tmp.c_str(), sk)) {
                cout << "No fue posible firmar el archivo" << endl;
                break;
            }
            cout << "Se firmo correctamente el archivo" << endl;
            break;

        //case 6 | verify sign and design file
        case 6:
            cout << "Ingresa el archivo a verificar" << endl;
            cin >> tmp;
            cout << "Ingresa el nombre a guardar" << endl;
            cin >> tmp2;
            if (verify_sign(tmp2.c_str(), tmp.c_str(), pk)) {
                cout << "No fue posible verificar la firma" << endl;
                break;
            }
            cout << "Se verifico y desfirmo correctamente el archivo" << endl;
            break;

        }

        if (status != 7)
            system("pause");
        system("cls");
    }
    return 0;

}

int test() {
    string name_key;
    string name_sign_keys;
    cout << "Ingresar nombre para llave de encriptado" << endl;
    std::cin >> name_key;
    name_key += ".key";

    cout << "Ingresa el nombre para el par para firmar" << endl;
    std::cin >> name_sign_keys;

    create_key(name_key.c_str());
    create_public_private_keys(name_sign_keys.c_str());

    //Lectura
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    read_file(name_key.c_str(), key, crypto_secretstream_xchacha20poly1305_KEYBYTES);

    read_file((name_sign_keys + ".pk").c_str(), pk, crypto_sign_PUBLICKEYBYTES);


    read_file((name_sign_keys + ".sk").c_str(), sk, crypto_sign_SECRETKEYBYTES);

    //encrypt("encry.txt", "PlainText.txt", key);
    //decrypt("decrypt.txt", "encry.txt", key);
    sign("signed.txt", "PlainText.txt", sk);
    verify_sign("design.txt", "signed.txt", pk);
    //decrypt("designdecrypt.txt", "design.txt", key);
    //decrypt("signedecripted.txt", "signcry.txt", key);
    return 0;
}
int read_file(const char* name, unsigned char* dir, unsigned int size) {
    /*Read a file usign the name variable, and save it on the dir array of size size*/
    FILE* file;
    fopen_s(&file,name, "rb");
    //If not readed return -1
    if (file == NULL) {
        return -1;
    }
    //Reads and save the size 
    fread(dir, 1, size, file);
    fclose(file);
    return 0;
}

unsigned char* read_file(const char* name, long * size) {
    /*Reads completely a file and returns the array and its size*/
    FILE* file;
    fopen_s(&file, name, "rb");
    //If file not readed return null
    if (file == NULL) {
        return NULL;
    }
    //counts the size of the file
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    //reads the file
    unsigned char* s = new unsigned char[fsize];
    fread(s, 1, fsize, file);
    fclose(file);
    
    //Returns
    *size = fsize;
    return s;
}



int save_file(unsigned char* text, const char* name, unsigned int size) {
    /*Saves a text into a file given its name and the size of the text*/
    FILE* file;
    fopen_s(&file, name, "wb");
    //If was no able to open return -1
    if (file == NULL) return -1;

    //Write to file
    fwrite(text,1,size,file);
    fclose(file);
    return 0;
}

int create_key(const char* name) {
    /*Creates a key and stores it on a file given its name
    The key is the key for chacha 20 poly 1305.
    */
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(key);
    return save_file(key, name, sizeof(key));
}

int create_public_private_keys(const char* name) {
    /*Creates a public key file and a private key file given the common name of the files
        public key is stored as:  name.pk
        private key is stored as: name.sk
    */
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    if (save_file(pk, (name + string(".pk")).c_str(), sizeof(pk)))
        return -1;
    return save_file(sk, (name + string(".sk")).c_str(), sizeof(sk));
};



static int
encrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    /*Given the name of the target file, the source file and the key encrypts the file
    usign chacha20 poly 1305
    
    The current function is a modification of the code given as example in libsodium 
    documentation: https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream
    */

    //Init of variables for bufer, header and files.
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    //Open of files
    fopen_s(&fp_s,source_file, "rb");
    fopen_s(&fp_t, target_file, "wb");
    //If any of the files was not able to open return -1
    if (!fp_s || !fp_t)return -1;

    //Implementation of chacha20 poly 1305 usign buffer and read of files.

    //Init of header and save it on file
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);

    //while read file is not completely readed
    do {
        //read from file and store it on buffer
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        //Select if its the last buffer
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        //encrypt buffer
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        //save encrypted buffer
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    //Close files
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}


static int
decrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    /*Given the name of the target file, the source file and the key desencrypts the file
    that used chacha20 poly 1305 encypting algorithm
    
    The current function is a modification of the code given as example in libsodium 
    documentation: https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream
    */
    
    //init variables of buffers, header and files
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    //Open files
    fopen_s(&fp_s, source_file, "rb");
    fopen_s(&fp_t, target_file, "wb");
    //If any of them is not opened return -1
    if (!fp_s || !fp_t)return -1;

    //Reads the header and inits the pull using it
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        //if was not able to init the pull return -1 and close files
        goto ret;
    }
    //read from file until it ends.
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        //Desencrypt of buffer.
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            //If not able to desencrypt return -1 and close files
            goto ret;
        }
        
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            //If reached end of file before finishing the stream return -1 and close files
            goto ret; 
        }
        //Saves on target file desencrypted buffer
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    //If reached this line means that the desencryption was completed.
    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int sign(const char * target, const char* source,  
        unsigned char sk[crypto_sign_SECRETKEYBYTES]) {
    /*Given a target file, source file and private key sign the
    source file and store it on target file.
    
    The current function is a modification of the code given as example in libsodium 
    documentation: https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures
    */

    //Reads the source file
    unsigned char* text;
    long size = 0;
    text = read_file(source, &size);

    //Init array for signed message
    unsigned char* signed_message = new unsigned char [crypto_sign_BYTES + (long long)size];
    unsigned long long signed_message_len;

    //Sign text
    int err = crypto_sign(signed_message, &signed_message_len,
        text, size, sk);

    //If a error was given return it
    if (err)return err;
    //Save the text to target file and return the result
    return save_file(signed_message, target, signed_message_len);
}

int verify_sign(const char* target, const char* source,
    unsigned char pk[crypto_sign_PUBLICKEYBYTES]) {
    /*Given a target file, source file and public key evaluate and remove sign from
    source file and store it on target file.
    
    The current function is a modification of the code given as example in libsodium
    documentation: https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures
    */

    //Read the source file and save it in text variable.
    unsigned char* text;
    long size = 0;
    text = read_file(source, &size);

    //Init variable unsigned message.
    unsigned char* unsigned_message = new unsigned char[(long long)size - crypto_sign_BYTES];
    unsigned long long unsigned_message_len;

    int err = crypto_sign_open(unsigned_message, &unsigned_message_len,
        text, size, pk);
    if (err)return err;
    return save_file(unsigned_message, target, unsigned_message_len);
}