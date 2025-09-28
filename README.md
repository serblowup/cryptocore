# cryptocore

Консольная утилита для шифрования и дешифрования файлов с использованием AES-128 в режимах ECB, CBC, CFB, OFB, CTR.

## Требования

- **Linux**
- **OpenSSL библиотеки**

### Режимы работы и синтаксис:

**1)****ECB**
- Шифруем
./cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ecb_cipher.bin
- Дешифруем
./cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ecb_cipher.bin --output ecb_decrypted.txt

**2)****CBC**
- Шифруем
./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cbc_cipher.bin
- Узнаем iv
xxd -l 16 cbc_cipher.bin
- Дешифруем c iv
./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv ... --input cbc_cipher.bin --output cbc_decrypted.txt
- Дешифруем без iv
./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc_cipher.bin --output cbc_decrypted.txt

**3)****CFB**
- Шифруем
./cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cfb_cipher.bin
- Дешифруем
./cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb_cipher.bin --output cfb_decrypted.txt

**4)****OFB**
- Шифруем
./cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ofb_cipher.bin
- Дешифруем
./cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ofb_cipher.bin --output ofb_decrypted.txt

**5)****CTR**
- Шифруем
./cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output ctr_cipher.bin
- Дешифруем
./cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ctr_cipher.bin --output ctr_decrypted.txt

#### Совместимость с OpenSSL:

**1)****Шифруем консольной утилитой, дешифруем с помощью OpenSSL**
- Шифруем
./cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" --output cipher.bin

dd if=cipher.bin of=iv.bin bs=16 count=1

dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1

- Дешифруем
openssl enc -aes-128-cbc -d -K 000102030405060708090A0B0C0D0E0F -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out decrypted.txt

**2)****Шифруем с помощью OpenSSL, дешифруем консольной утилитой**
- Шифруем
openssl enc -aes-128-cbc -K 000102030405060708090A0B0C0D0E0F -iv AABBCCDDEEFF00112233445566778899 -in "/home/sergey/cryptocore/cryptocore/tests/Primer.txt" -out openssl_cipher.bin

- Дешифруем
./cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090A0B0C0D0E0F --iv AABBCCDDEEFF00112233445566778899 --input openssl_cipher.bin --output decrypted.txt

