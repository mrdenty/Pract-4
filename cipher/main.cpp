#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include <cryptopp/aes.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[])
{
    string password, inputFilePath, outputFilePath, mode;
    cout << "Введите режим (encrypt/decrypt):" << endl;
    cin >> mode;

    if (mode == "encrypt") {
        cout << "Создайте пароль:" << endl;
        cin >> password;
        cout << "Введите путь к входному файлу:" << endl;
        cin >> inputFilePath;
        cout << "Введите путь к выходному файлу:" << endl;
        cin >> outputFilePath;

        byte key[SHA256::DIGESTSIZE];
        byte salt[AES::BLOCKSIZE];
        AutoSeededRandomPool randomPool;
        randomPool.GenerateBlock(salt, sizeof(salt));

        PKCS12_PBKDF<SHA256> pbkdf;
        pbkdf.DeriveKey(key, sizeof(key), 0, reinterpret_cast<const byte*>(password.data()), password.size(), salt, sizeof(salt), 1000, 0.0f);

        byte iv[AES::BLOCKSIZE];
        randomPool.GenerateBlock(iv, sizeof(iv));

        ofstream passFile("pass.txt");
        passFile << password;
        passFile.close();

        ofstream keyFile("key.dat", ios::binary);
        keyFile.write(reinterpret_cast<const char*>(key), sizeof(key));
        keyFile.close();

        ofstream ivFile("iv.dat", ios::binary);
        ivFile.write(reinterpret_cast<const char*>(iv), sizeof(iv));
        ivFile.close();

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), iv);

        ifstream inputFile(inputFilePath, ios::binary);
        if (!inputFile) {
            cerr << "Не удалось открыть файл для чтения: " << inputFilePath << endl;
            return 1;
        }

        ofstream outputFile(outputFilePath, ios::binary);
        FileSource(inputFile, true, new StreamTransformationFilter(encryptor, new FileSink(outputFile)));
    } else if (mode == "decrypt") {
        cout << "Введите пароль:" << endl;
        string enteredPassword;
        cin >> enteredPassword;

        string storedPassword;
        ifstream passFile("pass.txt");
        getline(passFile, storedPassword);
        passFile.close();

        if (storedPassword != enteredPassword) {
            cout << "Неправильный пароль\n";
            return 1;
        }

        cout << "Введите путь к зашифрованному файлу:" << endl;
        cin >> inputFilePath;
        cout << "Введите путь для расшифрованного файла:" << endl;
        cin >> outputFilePath;

        byte key[SHA256::DIGESTSIZE];
        ifstream keyFile("key.dat", ios::binary);
        keyFile.read(reinterpret_cast<char*>(key), sizeof(key));
        keyFile.close();

        byte iv[AES::BLOCKSIZE];
        ifstream ivFile("iv.dat", ios::binary);
        ivFile.read(reinterpret_cast<char*>(iv), sizeof(iv));
        ivFile.close();

        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, sizeof(key), iv);

        ifstream inputFile(inputFilePath, ios::binary);
        if (!inputFile) {
            cerr << "Не удалось открыть файл для чтения: " << inputFilePath << endl;
            return 1;
        }

        ofstream outputFile(outputFilePath, ios::binary);
             FileSource(inputFile, true, new StreamTransformationFilter(decryptor, new FileSink(outputFile)));
    } else {
        cerr << "Ошибка: неправильный режим - " << mode << endl;
        return 1;
    }
    return 0;
}
