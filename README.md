# cryptocore

*Консольная утилита для шифрования и дешифрования файлов с использованием AES-128 в режимах ECB, CBC, CFB, OFB, CTR, GCM. Собственная реализация хеш-функций SHA-256 и SHA3-256, имитовставок HMAC и AES-CMAC. Шифрование/дешифрование с дополнительными аутентифицируемыми данными (AAD) для режимов CBC, CFB, OFB, CTR.*

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
    ```bash
    ./cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ecb_cipher.bin
    ```
    - *Дешифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ecb_cipher.bin --output ecb_decrypted.txt
    ```

2. **CBC**
    - *Шифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cbc_cipher.bin 
    ```
    - *Узнаём iv*  
    ```bash
    xxd -l 16 cbc_cipher.bin
    ```
    - *Дешифруем c iv*  
    ```bash
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv ... --input cbc_cipher.bin --output cbc_decrypted.txt
    ```
    - *Дешифруем без iv*  
    ```bash
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc_cipher.bin --output cbc_decrypted.txt
    ```

3. **CFB**
    - *Шифруем*  
    ./cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cfb_cipher.bin  
    - *Дешифруем*  
    ./cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb_cipher.bin --output cfb_decrypted.txt

4. **OFB**
    - *Шифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ofb_cipher.bin 
    ```
    - *Дешифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ofb_cipher.bin --output ofb_decrypted.txt
    ```

5. **CTR**
    - *Шифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ctr_cipher.bin
    ```
    - *Дешифруем*  
    ```
    ./cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ctr_cipher.bin --output ctr_decrypted.txt
    ```

6. **Шифрование без ключа**
    - *Шифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode cbc --encrypt --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output no_key.bin 
    ```
    - *Шифрование успешно, сгенерированный ключ выводится для пользователя.*  
    ```bash
    Generated random key: 03ced7bc015ab154663dac4fa5e13246  
    Success: /home/sergey/cryptocore/cryptocore/tests/Primer.txt -> no_key.bin
    ```
    - *Дешифруем (только с введённым ключом)*  
    ```bash
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 03ced7bc015ab154663dac4fa5e13246 --input no_key.bin --output no_key.txt
    ```
    
7. **GCM**

    - *Шифруем без ключа и без дополнительных аутентифицируемых данных (AAD)*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --encrypt --input "/home/sergey/Рабочий стол/Primer3.txt" --output ciphertext.bin
    Generated random key: 8a44dedfc9d263010e2987bc7e2c530b
    Info: No AAD provided, using empty AAD
    GCM encryption completed successfully
    Output written to: ciphertext.bin
    ```
    - *Дешифруем с сгенерированым ключом*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --decrypt --key 8a44dedfc9d263010e2987bc7e2c530b --input ciphertext.bin --output decrypted.txt
    Info: Nonce will be read from file (first 12 bytes) for GCM decryption
    Info: No AAD provided, using empty AAD
    Reading nonce from file (first 12 bytes)
    GCM decryption completed successfully
    Output written to: decrypted.txt
    ```
    
    - *Шифруем с ключом и без дополнительных аутентифицируемых данных (AAD)*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --output ciphertext.bin
    Info: No AAD provided, using empty AAD
    GCM encryption completed successfully
    Output written to: ciphertext.bin
    ```
    - *Дешифруем*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt
    Info: Nonce will be read from file (first 12 bytes) for GCM decryption
    Info: No AAD provided, using empty AAD
    Reading nonce from file (first 12 bytes)
    GCM decryption completed successfully
    Output written to: decrypted.txt
    ```
    
    - *Шифруем с ключом и с дополнительными аутентифицируемыми данными (AAD)*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --output ciphertext.bin --aad aabbccddeeff0011223344556677
    Info: Using AAD: aabbccddeeff0011223344556677
    GCM encryption completed successfully
    Output written to: ciphertext.bin
    ```
    - *Дешифруем с ключом и с дополнительными аутентифицируемыми данными (AAD)*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt --aad aabbccddeeff0011223344556677
    Info: Nonce will be read from file (first 12 bytes) for GCM decryption
    Info: Using AAD: aabbccddeeff0011223344556677
    Reading nonce from file (first 12 bytes)
    GCM decryption completed successfully
    Output written to: decrypted.txt
    ```
    
    - *Шифрование с указанием iv (nonce)*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --iv 000000000000000000000000 --input "/home/sergey/Рабочий стол/Primer3.txt" 
    --output ciphertext_with_iv.bin --aad aabbccddeeff0011223344556677
    Warning: User-provided nonce will be used for GCM encryption
    Info: Using AAD: aabbccddeeff0011223344556677
    GCM encryption completed successfully
    Output written to: ciphertext_with_iv.bin
    ```
    - *Дешифрование с указанием iv (nonce)*
    ```bash
    ./cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --iv 000000000000000000000000 --input ciphertext_with_iv.bin 
    --output decrypted_with_iv.txt --aad aabbccddeeff0011223344556677eff0011223344556677
    Info: Using AAD: aabbccddeeff0011223344556677
    Using user-provided nonce via --iv
    GCM decryption completed successfully
    Output written to: decrypted_with_iv.txt
    ```

8. **Шифрование/дешифрование с дополнительными аутентифицируемыми данными (AAD) для режимов CBC, CFB, OFB, CTR**
    
    1. **CBC**
        - *Шифрование в режиме CBC c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer4.pdf" 
        --output encrypted_cbc.bin --aad aabbccddeeff0011223344556677
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 1
        ETM (CBC) encryption completed successfully
        Output written to: encrypted_cbc.bin
        ```
        - *Дешифрование в режиме CBC c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input encrypted_cbc.bin 
        --output decrypted_cbc.pdf --aad aabbccddeeff0011223344556677
        Warning: --iv not provided for decryption in mode 1. Will try to read from file.
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 1
        ETM (CBC) decryption completed successfully
        Output written to: decrypted_cbc.pdf
        ```
        
    2. **CFB**
        - *Шифрование в режиме CFB c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode cfb --encrypt --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer4.pdf" 
        --output encrypted_cfb.bin --aad aabbccddeeff0011223344556677
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 2
        ETM (CFB) encryption completed successfully
        Output written to: encrypted_cfb.bin
        ```
        - *Дешифрование в режиме CFB c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode cfb --decrypt --key 00112233445566778899aabbccddeeff --input encrypted_cfb.bin 
        --output decrypted_cfb.pdf --aad aabbccddeeff0011223344556677
        Warning: --iv not provided for decryption in mode 2. Will try to read from file.
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 2
        ETM (CFB) decryption completed successfully
        Output written to: decrypted_cfb.pdf
        ```
        
    3. **OFB**
        - *Шифрование в режиме OFB c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode ofb --encrypt --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer4.pdf" 
        --output encrypted_ofb.bin --aad aabbccddeeff0011223344556677
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 3
        ETM (OFB) encryption completed successfully
        Output written to: encrypted_ofb.bin
        ```
        - *Дешифрование в режиме OFB c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode ofb --decrypt --key 00112233445566778899aabbccddeeff --input encrypted_ofb.bin 
        --output decrypted_ofb.pdf --aad aabbccddeeff0011223344556677
        Warning: --iv not provided for decryption in mode 3. Will try to read from file.
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 3
        ETM (OFB) decryption completed successfully
        Output written to: decrypted_ofb.pdf
        ```
        
    4. **CTR**
        - *Шифрование в режиме CTR c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode ctr --encrypt --key 00112233445566778899aabbccddeeff --iv 00000000000000000000000000000000 --input "/home/sergey/Рабочий стол/Primer4.pdf"
        --output encrypted_ctr.bin --aad aabbccddeeff0011223344556677
        Warning: --iv is ignored during encryption (IV is generated automatically)
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 4
        ETM (CTR) encryption completed successfully
        Output written to: encrypted_ctr.bin
        ```
        - *Дешифрование в режиме CTR c дополнительными аутентифицируемыми данными (AAD)*
        ```bash
        ./cryptocore --algorithm aes --mode ctr --decrypt --key 00112233445566778899aabbccddeeff --iv 00000000000000000000000000000000 --input encrypted_ctr.bin 
        --output decrypted_ctr.pdf \--aad aabbccddeeff0011223344556677
        Info: Using AAD: aabbccddeeff0011223344556677
        Info: Encrypt-then-MAC (ETM) mode activated for mode 4
        ETM (CTR) decryption completed successfully
        Output written to: decrypted_ctr.pdf
        ```
        
9. **Подкоманда dgst**

    1. **SHA-256**
        - *Вывод хеша в консоли*  
        ```bash
        ./cryptocore dgst --algorithm sha256 --input "/home/sergey/Рабочий стол/Primer2.txt"  
        f41d8556f033c9484d887ebfcd3056f00bbddce12f66203d5d688beaec98eb35 /home/sergey/Рабочий стол/Primer2.txt
        ```
        - *Сохранение хеша в файл*  
        ```bash
        ./cryptocore dgst --algorithm sha256 --input "/home/sergey/Рабочий стол/Primer2.txt" --output Primer2.sha256  
        Hash written to: Primer2.sha256
        ```
        
    2. **SHA3-256**
        - *Вывод хеша в консоли*  
        ```bash
        ./cryptocore dgst --algorithm sha3-256 --input "/home/sergey/Рабочий стол/Primer2.txt"  
        485a73a2fe5f619e92c218d2d64f48bffb3b9a7f69fa210bc4cf94c95f4ae1df /home/sergey/Рабочий стол/Primer2.txt
        ```
        - *Сохранение хеша в файл*  
        ```bash
        ./cryptocore dgst --algorithm sha3-256 --input "/home/sergey/Рабочий стол/Primer2.txt" --output Primer2.sha3  
        Hash written to: Primer2.sha3
        ```
        
    3. **Идентичность результата системным командам**
        - *SHA-256*  
        ```bash
        sha256sum "/home/sergey/Рабочий стол/Primer2.txt"  
        f41d8556f033c9484d887ebfcd3056f00bbddce12f66203d5d688beaec98eb35  /home/sergey/Рабочий стол/Primer2.txt
        ```
        - *SHA3-256*  
        ```bash
        sha3sum -a 256 "/home/sergey/Рабочий стол/Primer2.txt"  
        485a73a2fe5f619e92c218d2d64f48bffb3b9a7f69fa210bc4cf94c95f4ae1df  /home/sergey/Рабочий стол/Primer2.txt
        ```
        
    4. **HMAC**
        - *Вывод в консоли*  
        ```bash
        ./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt"  
        HMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        9c1540666a2f5f6c822efd3329a38f8dbf3d24401ff34f0306948f88d1a954d2 /home/sergey/Рабочий стол/Primer3.txt
        ```
        - *Сохранение в файл*  
        ```bash
        ./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --output Primer3.hmac  
        HMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        HMAC written to: Primer3.hmac
        ```
        - *Верификация*  
        ```bash
        ./cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --verify Primer3.hmac  
        HMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        [OK] HMAC verification successful
        ```
        
    5. **AES-CMAC**
        - *Вывод в консоли*  
        ```bash
        ./cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt"  
        CMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        da6af30f94c2d832f3eacbdf41b9d158 /home/sergey/Рабочий стол/Primer3.txt
        ```
        - *Сохранение в файл*  
        ```bash
        ./cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --output Primer3.cmac  
        CMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        CMAC written to: Primer3.cmac 
        ```
        - *Верификация*  
        ```bash
        ./cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input "/home/sergey/Рабочий стол/Primer3.txt" --verify Primer3.cmac  
        CMAC computed for 103 bytes from '/home/sergey/Рабочий стол/Primer3.txt'  
        [OK] CMAC verification successful
        ```
        
10. **Запуск тестов**
    - *Тесты генератора ключей*  
    ```bash
    ./cryptocore --input --test-keys
    ```
    - *NIST-тесты*  
    ```bash
    ./cryptocore --input --test-nist
    ```
    *Результат NIST-тестов представлен в NIST_results.txt*  
    
    - *Тесты хеш-функций*  
    ```bash
    ./cryptocore --input --test-hash
    ```
    - *Тесты имитовставок*  
    ```bash
    ./cryptocore --input --test-mac
    ```
    - *Тесты режима GCM и режимов шифрования с аутентификацией и присоединенными данными*
    ```bash
    ./cryptocore --input --test-aead
    ```
    
##### Совместимость с OpenSSL:

1. **Шифруем консольной утилитой, дешифруем с помощью OpenSSL**
    - *Шифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cipher.bin  
      dd if=cipher.bin of=iv.bin bs=16 count=1  
      dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1
    ```
    - *Дешифруем*  
    ```bash
    openssl enc -aes-128-cbc -d -K 000102030405060708090A0B0C0D0E0F -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out decrypted.txt
    ```

2. **Шифруем с помощью OpenSSL, дешифруем консольной утилитой**
    - *Шифруем*  
    ```bash
    openssl enc -aes-128-cbc -K 000102030405060708090A0B0C0D0E0F -iv AABBCCDDEEFF00112233445566778899 -in "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" -out openssl_cipher.bin
    ```
    - *Дешифруем*__
    ```bash
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090A0B0C0D0E0F --iv AABBCCDDEEFF00112233445566778899 --input openssl_cipher.bin --output decrypted.txt
    ```
