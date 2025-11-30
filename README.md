# cryptocore

*Консольная утилита для шифрования и дешифрования файлов с использованием AES-128 в режимах ECB, CBC, CFB, OFB, CTR. Собственная реализация хеш-функций SHA-256 и SHA3-256, имитовставок HMAC и AES-CMAC.*

## Требования

- *Linux*
- *GCC*
- *OpenSSL библиотеки*
- *Утилита XXD (пакет vim)*

### Сборка проекта

- **git clone https://github.com/serblowup/cryptocore.git**
- **cd cryptocore**
- **make clean**
- **make all**

#### Команды и их синтаксис:

1. **ECB**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ecb_cipher.bin  
    - *Дешифруем*  
    ./cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ecb_cipher.bin --output ecb_decrypted.txt

2. **CBC**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cbc_cipher.bin  
    - *Узнаём iv*  
    xxd -l 16 cbc_cipher.bin  
    - *Дешифруем c iv*  
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv ... --input cbc_cipher.bin --output cbc_decrypted.txt  
    - *Дешифруем без iv*  
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc_cipher.bin --output cbc_decrypted.txt

3. **CFB**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cfb_cipher.bin  
    - *Дешифруем*  
    ./cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb_cipher.bin --output cfb_decrypted.txt

4. **OFB**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ofb_cipher.bin  
    - *Дешифруем*  
    ./cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ofb_cipher.bin --output ofb_decrypted.txt

5. **CTR**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ctr_cipher.bin  
    - *Дешифруем*  
    ./cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ctr_cipher.bin --output ctr_decrypted.txt

6. **Шифрование без ключа**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode cbc --encrypt --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output no_key.bin  
    - *Шифрование успешно, сгенерированный ключ выводится для пользователя.*  
    Generated random key: 03ced7bc015ab154663dac4fa5e13246  
    Success: /home/sergey/cryptocore/cryptocore/tests/Primer.txt -> no_key.bin  
    - *Дешифруем (только с введённым ключом)*  
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 03ced7bc015ab154663dac4fa5e13246 --input no_key.bin --output no_key.txt
    
7. **Подкоманда dgst**

    1. **SHA-256**
        - *Вывод хеша в консоли*  
        ./cryptocore dgst --algorithm sha256 --input "/home/sergey/Рабочий стол/Primer2.txt"  
        f41d8556f033c9484d887ebfcd3056f00bbddce12f66203d5d688beaec98eb35 /home/sergey/Рабочий стол/Primer2.txt  
        - *Сохранение хеша в файл*  
        ./cryptocore dgst --algorithm sha256 --input "/home/sergey/Рабочий стол/Primer2.txt" --output Primer2.sha256  
        Hash written to: Primer2.sha256
        
    2. **SHA3-256**
        - *Вывод хеша в консоли*  
        ./cryptocore dgst --algorithm sha3-256 --input "/home/sergey/Рабочий стол/Primer2.txt"  
        485a73a2fe5f619e92c218d2d64f48bffb3b9a7f69fa210bc4cf94c95f4ae1df /home/sergey/Рабочий стол/Primer2.txt  
        - *Сохранение хеша в файл*  
        ./cryptocore dgst --algorithm sha3-256 --input "/home/sergey/Рабочий стол/Primer2.txt" --output Primer2.sha3  
        Hash written to: Primer2.sha3
        
    3. **Идентичность результата системным командам**
        - *SHA-256*  
        sha256sum "/home/sergey/Рабочий стол/Primer2.txt"  
        f41d8556f033c9484d887ebfcd3056f00bbddce12f66203d5d688beaec98eb35  /home/sergey/Рабочий стол/Primer2.txt  
        - *SHA3-256*  
        sha3sum -a 256 "/home/sergey/Рабочий стол/Primer2.txt"  
        485a73a2fe5f619e92c218d2d64f48bffb3b9a7f69fa210bc4cf94c95f4ae1df  /home/sergey/Рабочий стол/Primer2.txt
        
    4. **HMAC**
        - *Вывод в консоли*  
        ./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt"  
        HMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        9c1540666a2f5f6c822efd3329a38f8dbf3d24401ff34f0306948f88d1a954d2 /home/sergey/Рабочий стол/Primer3.txt  
        - *Сохранение в файл*  
        ./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --output Primer3.hmac  
        HMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        HMAC written to: Primer3.hmac  
        - *Верификация*  
        ./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --verify Primer3.hmac  
        HMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        |OK| HMAC verification successful
        
    5. **AES-CMAC**
        - *Вывод в консоли*  
        ./cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt"  
        CMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        da6af30f94c2d832f3eacbdf41b9d158 /home/sergey/Рабочий стол/Primer3.txt  
        - *Сохранение в файл*  
        ./cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --output Primer3.cmac  
        CMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        CMAC written to: Primer3.cmac  
        - *Верификация*  
        ./cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --verify Primer3.cmac  
        CMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        |OK| CMAC verification successful
        
8. **Запуск тестов**
    - *Тесты генератора ключей*  
    ./cryptocore --input --test-keys  
    - *NIST-тесты*  
    ./cryptocore --input --test-nist  
    *Результат NIST тестов представлен в NIST_results.txt*  
    - *Тесты хеш-функций*  
    ./cryptocore --input --test-hash  
    - *Тесты имитовставок*  
    ./cryptocore --input --test-mac
    
##### Совместимость с OpenSSL:

1. **Шифруем консольной утилитой, дешифруем с помощью OpenSSL**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cipher.bin  
      dd if=cipher.bin of=iv.bin bs=16 count=1  
      dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1  
    - *Дешифруем*  
    openssl enc -aes-128-cbc -d -K 000102030405060708090A0B0C0D0E0F -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out decrypted.txt

2. **Шифруем с помощью OpenSSL, дешифруем консольной утилитой**
    - *Шифруем*  
    openssl enc -aes-128-cbc -K 000102030405060708090A0B0C0D0E0F -iv AABBCCDDEEFF00112233445566778899 -in "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" -out openssl_cipher.bin  
    - Дешифруем  
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090A0B0C0D0E0F --iv AABBCCDDEEFF00112233445566778899 --input openssl_cipher.bin --output decrypted.txt
