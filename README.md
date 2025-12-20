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
    ```bash
    ./cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cfb_cipher.bin
    ```
    - *Дешифруем*  
    ```bash
    ./cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb_cipher.bin --output cfb_decrypted.txt
    ```

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
10. **Подкоманда derive**
     
     1. **PBKDF2**
         - *Ввод только пароля*
         ```bash
         ./cryptocore derive --algorithm pbkdf2 --password 'MyPassword'
         Key Derivation Parameters:
           Algorithm:   pbkdf2
           Iterations:  100000
           Key Length:  32 bytes
           Mode:        PBKDF2-HMAC-SHA256
           Salt:        Randomly generated (16 bytes)
           Password:    Provided (10 characters)
         Deriving key... Done
         Result: c483d6d7b0e07e07af73c9816cc4c2bcaafbfd0b82081c1fb9df19105cb64c38 d1c624b88875f9e417fd15e13df199d3
         ```
         - *Ввод пароля и соли в hex-формате*
         ```bash
         ./cryptocore derive --algorithm pbkdf2 --password 'test' --salt a1b2c3d4e5f601234567890123456789
         DEBUG: Salt interpreted as hex string, length: 16 bytes
         Key Derivation Parameters:
           Algorithm:   pbkdf2
           Iterations:  100000
           Key Length:  32 bytes
           Mode:        PBKDF2-HMAC-SHA256
           Salt:        Provided (a1b2c3d4e5f601234567890123456789, 16 bytes)
           Password:    Provided (4 characters)
         Deriving key... Done
         Result: 6080c89692fc27a7e0af08716546e996c2c3bbbc72ca6490980261871ba72846 a1b2c3d4e5f601234567890123456789
         ```
        - *Ввод пароля и соли в текстовом формате*
        ```bash
        ./cryptocore derive --algorithm pbkdf2 --password 'test' --salt 'my_salt_string'
        DEBUG: Salt interpreted as text string, length: 14 bytes
        Key Derivation Parameters:
          Algorithm:   pbkdf2
          Iterations:  100000
          Key Length:  32 bytes
          Mode:        PBKDF2-HMAC-SHA256
          Salt:        Provided (6d795f73616c745f737472696e67, 14 bytes)
          Password:    Provided (4 characters)
        Deriving key... Done
        Result: eab7d7ed229615d1950a6d1055ed80d1bd5c6068c20546c8a18185e009c7cf68 6d795f73616c745f737472696e67
        ```
        - *Ввод пароля, соли и количества итераций*
        ```bash
        ./cryptocore derive --algorithm pbkdf2 --password 'test' --salt 00000000000000000000000000000000 --iterations 500000
        DEBUG: Salt interpreted as hex string, length: 16 bytes
        Key Derivation Parameters:
          Algorithm:   pbkdf2
          Iterations:  500000
          Key Length:  32 bytes
          Mode:        PBKDF2-HMAC-SHA256
          Salt:        Provided (00000000000000000000000000000000, 16 bytes)
          Password:    Provided (4 characters)
        Deriving key... Done
        Result: 885ef65ad253c80860b854e95afd74ce12b2aac4f726be8b9209e5fd59027532 00000000000000000000000000000000
        ```
        - *Ввод пароля, соли и длины ключа*
        ```bash
        ./cryptocore derive --algorithm pbkdf2 --password 'test' --salt 00000000000000000000000000000000 --length 48
        DEBUG: Salt interpreted as hex string, length: 16 bytes
        Key Derivation Parameters:
          Algorithm:   pbkdf2
          Iterations:  100000
          Key Length:  48 bytes
          Mode:        PBKDF2-HMAC-SHA256
          Salt:        Provided (00000000000000000000000000000000, 16 bytes)
          Password:    Provided (4 characters)
        Deriving key... Done
        Result: da3a2737bbf7ddc300befff667a52ed11f95f79a0ff52f24d70890d6c7523c3d4dc362b6311067f4d95c83923a4b7b0a 00000000000000000000000000000000
        ```
        - *Ввод всех параметров*
        ```bash
        ./cryptocore derive --algorithm pbkdf2 --password 'MySecurePass123!' --salt a1b2c3d4e5f601234567890123456789 --iterations 100000 --length 64
        DEBUG: Salt interpreted as hex string, length: 16 bytes
        Key Derivation Parameters:
          Algorithm:   pbkdf2
          Iterations:  100000
          Key Length:  64 bytes
          Mode:        PBKDF2-HMAC-SHA256
          Salt:        Provided (a1b2c3d4e5f601234567890123456789, 16 bytes)
          Password:    Provided (16 characters)
        Deriving key... Done
        Result: f861994b137441ac453a322674ed5101ebb6b43e31e3f0a46052bb85fa7e2a6f6c88cd5eaa799850f0076066baa9000521205de1b3cdf38711c67b1c858aa63c a1b2c3d4e5f601234567890123456789
        ```
        - *Ввод всех параметров и сохранение в файл*
        ```bash
        ./cryptocore derive --algorithm pbkdf2 --password 'app_key' --salt 'fixedappsalt' --iterations 10000 --length 64 --output app_key.bin
        DEBUG: Salt interpreted as text string, length: 12 bytes
        Key Derivation Parameters:
          Algorithm:   pbkdf2
          Iterations:  10000
          Key Length:  64 bytes
          Mode:        PBKDF2-HMAC-SHA256
          Salt:        Provided (666978656461707073616c74, 12 bytes)
          Password:    Provided (7 characters)
        Deriving key... Done
        Result: 63f623c88aab4cdff5e299272e3fd6d1d7e02136a7aecff314444003c0d450eb17074d8af05895f0cdea5625a11b526810faad214d0a6a7c2d2e2a2a10f6413a 666978656461707073616c74
        Key written to: app_key.bin (64 bytes)

        ls -la app_key.bin
        -rw-r--r-- 1 sergey sergey 64 дек 20 16:50 app_key.bin

        xxd app_key.bin | head -2
        00000000: 63f6 23c8 8aab 4cdf f5e2 9927 2e3f d6d1  c.#...L....'.?..
        00000010: d7e0 2136 a7ae cff3 1444 4003 c0d4 50eb  ..!6.....D@...P.
        ```

    2. **HKDF**
        - *Минимальный ввод аргументов*
        ```bash
        ./cryptocore derive --algorithm hkdf --master-key 00112233445566778899aabbccddeeff --context 'encryption'
        Key Derivation Parameters:
          Algorithm:   hkdf
          Iterations:  100000
          Key Length:  32 bytes
          Mode:        HKDF
          Context:     encryption
        Deriving key... Done
        Result: 422769d806a19fa40ba5e3785b1935153884e3450d1e5d4ba4db53068b27c317
        ```
        - *Ввод длины ключа*
        ```bash
        ./cryptocore derive --algorithm hkdf --master-key 00112233445566778899aabbccddeeff --context 'authentication' --length 48
        Key Derivation Parameters:
          Algorithm:   hkdf
          Iterations:  100000
          Key Length:  48 bytes
          Mode:        HKDF
          Context:     authentication
        Deriving key... Done
        Result: 89ac28ebc04a105432d0bb6d1962567807b8e976c82b4b96fd8ea6e2037b338f14316ac45cfac6410e21620564c3b9cf
        ```
        - *Ввод флага --key (вместо флага --master-key)*
        ```bash
        ./cryptocore derive --algorithm hkdf --key 00112233445566778899aabbccddeeff --context 'encryption' --length 32
        Key Derivation Parameters:
          Algorithm:   hkdf
          Iterations:  100000
          Key Length:  32 bytes
          Mode:        HKDF
          Context:     encryption
        Deriving key... Done
        Result: 422769d806a19fa40ba5e3785b1935153884e3450d1e5d4ba4db53068b27c317
        ```
        - *Ввод всех параметров и сохранение в файл*
        ```bash
        ./cryptocore derive --algorithm hkdf --master-key 00112233445566778899aabbccddeeff --context 'database_key' --length 32 --output hkdf_key.bin
        Key Derivation Parameters:
          Algorithm:   hkdf
          Iterations:  100000
          Key Length:  32 bytes
          Mode:        HKDF
          Context:     database_key
        Deriving key... Done
        Result: 7bd46e328cf041f4c537a3b74d69c3bfbe33925311ae946c0e994d7f612dfdce
        Key written to: hkdf_key.bin (32 bytes)
        
        ls -la hkdf_key.bin
        -rw-r--r-- 1 sergey sergey 32 дек 20 16:54 hkdf_key.bin
        
        xxd hkdf_key.bin | head -2
        00000000: 7bd4 6e32 8cf0 41f4 c537 a3b7 4d69 c3bf  {.n2..A..7..Mi..
        00000010: be33 9253 11ae 946c 0e99 4d7f 612d fdce  .3.S...l..M.a-..
        ```
        
11. **Запуск тестов**
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
    - *Тесты функций формирования ключа (KDF)*
    ```bash
    ./cryptocore --input --test-kdf
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
    - *Дешифруем*
    ```bash
    ./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090A0B0C0D0E0F --iv AABBCCDDEEFF00112233445566778899 --input openssl_cipher.bin --output decrypted.txt
    ```
