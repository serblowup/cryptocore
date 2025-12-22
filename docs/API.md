API

1. Структуры данных

*config_t*

Основная структура конфигурации для работы CLI-инструмента.

```c

typedef struct {

algorithm_t algorithm;

cipher_mode_t mode;

operation_mode_t operation;

BYTE key[AES_128_KEY_SIZE];

BYTE iv[IV_SIZE];

BYTE nonce[GCM_NONCE_SIZE];

BYTE aad\_data[MAX_AAD_SIZE];

size_t aad_len;

char input_file[MAX_PATH_LEN];

char output_file[MAX_PATH_LEN];

char verify_file[MAX_PATH_LEN];

char aad_hex[MAX_PATH_LEN];

char password[MAX_PATH_LEN];

char salt_hex[MAX_PATH_LEN * 2];

unsigned int iterations;

size_t key_length;

size_t salt_len;

BYTE salt_data[MAX_SALT_LENGTH];

char kdf_algorithm[MAX_PATH_LEN];

int iv_provided;

int nonce_provided;

int aad_provided;

int force_format;

int key_provided;

int hmac_mode;

int cmac_mode;

int verify_mode;

int gcm_mode;

int etm_mode;

int salt_provided;

int password_provided;

int derive_mode;

} config_t;
```

Поля:
```

algorithm – используемый алгоритм (см. algorithm_t)

mode – режим шифрования (см. cipher_mode_t)

operation – операция: шифрование/дешифрование (см. operation_mode_t)

key – ключ шифрования (16 байт для AES-128)

iv – вектор инициализации (16 байт)

nonce – одноразовый номер для GCM (12 байт)

aad_data – дополнительные аутентифицируемые данные

aad_len – длина AAD в байтах

input_file – путь к входному файлу

output_file – путь к выходному файлу

verify_file – путь к файлу для проверки (HMAC/CMAC)

aad_hex – AAD в шестнадцатеричном формате (строка)

password – пароль для KDF

salt_hex – соль в шестнадцатеричном формате

iterations – количество итераций для PBKDF2

key_length – длина генерируемого ключа для KDF

salt_len – длина соли в байтах

salt_data – данные соли

kdf_algorithm – название алгоритма KDF
```

Флаги:
```
iv_provided – 1, если IV предоставлен пользователем

nonce_provided – 1, если nonce предоставлен пользователем

aad_provided – 1, если AAD предоставлен

key_provided – 1, если ключ предоставлен

hmac_mode – 1, если используется HMAC

cmac_mode – 1, если используется CMAC

verify_mode – 1, если выполняется проверка

gcm_mode – 1, если используется режим GCM

etm_mode – 1, если используется Encrypt-then-MAC

salt_provided – 1, если соль предоставлена

password_provided – 1, если пароль предоставлен

derive_mode – 1, если выполняется вывод ключа
```

Перечисления

operation_mode_t

```c

typedef enum {

MODE_ENCRYPT,

MODE_DECRYPT,

MODE_DERIVE

} operation_mode_t;
```

cipher_mode_t

```c

typedef enum {

MODE_ECB,

MODE_CBC,

MODE_CFB,

MODE_OFB,

MODE_CTR,

MODE_GCM

} cipher_mode_t;
```

algorithm_t

```c

typedef enum {

ALG_AES,

ALG_SHA256,

ALG_SHA3_256,

ALG_HMAC,

ALG_CMAC,

ALG_PBKDF2,

ALG_HKDF

} algorithm_t;
```

Константы
```

Константа	Значение	Описание

BLOCK_SIZE	16	Размер блока AES в байтах

AES_128_KEY_SIZE	16	Размер ключа AES-128 в байтах

MAX_PATH_LEN	1024	Максимальная длина пути к файлу

IV_SIZE	16	Размер вектора инициализации в байтах

GCM_NONCE_SIZE	12	Размер nonce для GCM в байтах

GCM_TAG_SIZE	16	Размер тега аутентификации GCM в байтах

MAX_AAD_SIZE	1024	Максимальный размер AAD в байтах

MAX_KDF_KEY_LENGTH	256	Максимальная длина ключа для KDF в байтах

MAX_SALT_LENGTH	64	Максимальная длина соли в байтах
```

2. cryptocore.csprng

*generate_random_bytes()*

Генерирует криптографически стойкие случайные байты.

Параметры:
```

buffer (uint8_t*) – указатель на буфер для записи случайных данных

num_bytes (size_t) – количество байт для генерации
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке
```

Вызывает:
```

CSPRNG_ERROR – если параметры некорректны или RAND_bytes завершился ошибкой
```

Пример:

```c

uint8_t random_buffer[32];

if (generate_random_bytes(random_buffer, 32) != 1) {

fprintf(stderr, "Failed to generate random bytes\n");

}
```

*generate_random_key()*

Генерирует случайный 128-битный ключ AES.

Параметры:
```

key (BYTE*) – указатель на буфер для записи ключа (16 байт)
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке
```

Пример:

```c

BYTE aes_key[AES_128_KEY_SIZE];

if (generate_random_key(aes_key) != 1) {

fprintf(stderr, "Failed to generate random key\n");

}
```

*is_weak_key()*

Проверяет, является ли ключ слабым.

Параметры:
```

key (const BYTE*) – указатель на ключ для проверки

key_len (size_t) – длина ключа в байтах
```

Возвращает:
```

int – 1 если ключ слабый, 0 если ключ нормальный
```

Пример:

```c

BYTE key[16] = {0};

if (is_weak_key(key, 16)) {

printf("Warning: Weak key detected\n");

}
```

Соображения безопасности:
```

Обнаруживает тривиальные ключи (все нули, все единицы)

Обнаруживает последовательные значения

Рекомендуется проверять все пользовательские ключи
```

3. cryptocore.file_io

*read_file()*

Читает содержимое файла в буфер.

Параметры:
```

filename (const char*) – путь к файлу для чтения

data (BYTE**) – указатель на указатель для размещения данных

data_len (size_t*) – указатель для сохранения длины данных
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке
```

Вызывает:
```

stderr сообщения об ошибках открытия файла, выделения памяти или чтения
```

Пример:

```c

BYTE *file_data;

size_t file_size;

if (read_file("input.bin", &file_data, &file_size)) {

printf("Read %zu bytes\n", file\_size);

free(file_data);

}
```

*write_file()*

Записывает данные в файл.

Параметры:
```

filename (const char*) – путь к файлу для записи

data (const BYTE*) – указатель на данные для записи

data_len (size_t) – длина данных в байтах
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке
```

Пример:

```c

BYTE data[] = {0x01, 0x02, 0x03};

if (write_file("output.bin", data, sizeof(data))) {

printf("File written successfully\n");

}
```

*process_file_in_chunks()*

Обрабатывает файл по частям заданного размера.

Параметры:
```

filename (const char*) – путь к файлу

process_chunk (функция) – указатель на функцию обработки чанка

context (void*) – контекст для функции обработки

chunk_size (size_t) – размер чанка в байтах
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке
```

Пример:

```c

void process\_chunk(const BYTE \*chunk, size\_t chunk\_len, void \*context) {


}

if (process_file_in_chunks("large_file.bin", process_chunk, NULL, 8192)) {

printf("File processed successfully\n");

}
```

4. cryptocore.cli_parser

*parse_arguments()*

Парсит аргументы командной строки и заполняет структуру конфигурации.

Параметры:
```

argc (int) – количество аргументов

argv (char*[]) – массив строк аргументов

config (config_t*) – указатель на структуру конфигурации
```

Возвращает:
```

int – 1 при успешном парсинге, 0 при ошибке
```

Вызывает:
```

stderr сообщения об ошибках валидации аргументов

Автоматически вызывает print_usage() при --help
```

Пример:

```c

config_t config;

if (!parse_arguments(argc, argv, &config)) {

return 1;

}
```

Особенности:
```

Поддерживает все режимы работы (шифрование, хэширование, MAC, KDF)

Автоматически генерирует случайные ключи при необходимости

Проверяет корректность шестнадцатеричных строк

Поддерживает команды тестирования
```

*print_usage()*

Выводит справку по использованию программы.

Параметры:

program_name (const char*) – имя программы (argv[0])

Пример:

```c

print_usage(argv[0]);
```

*hex_string_to_bytes()*

Преобразует шестнадцатеричную строку в массив байт.

Параметры:
```

hex_string (const char*) – входная шестнадцатеричная строка

bytes (BYTE*) – буфер для записи байт

bytes_len (size_t) – ожидаемая длина в байтах
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке (некорректная длина или символы)
```

Пример:

```c

BYTE key[16];

if (hex_string_to_bytes("00112233445566778899aabbccddeeff", key, 16)) {

printf("Key parsed successfully\n");

}
```

*is_hex_string()*

Проверяет, является ли строка корректной шестнадцатеричной строкой.

Параметры:
```

str (const char*) – строка для проверки
```

Возвращает:
```

int – 1 если все символы шестнадцатеричные, 0 в противном случае
```

Пример:

```c

if (is_hex_string("123abc")) {

printf("Valid hex string\n");

}
```

5. cryptocore.aes

*Функции режимов шифрования*

Все функции шифрования/дешифрования имеют схожие сигнатуры:

Параметры:
```

key (const BYTE*) – 128-битный ключ AES

input (const BYTE*) – входные данные

input_len (size_t) – длина входных данных

output (BYTE**) – указатель на указатель для выходных данных

output_len (size_t*) – указатель для длины выходных данных
```

Возвращает:
```

int – 1 при успехе, 0 при ошибке
```

Вызывает:
```

stderr сообщения об ошибках выделения памяти или операций OpenSSL
```

*ecb_encrypt() / ecb_decrypt()*

Шифрование/дешифрование в режиме ECB.

Особенности:
```

Использует PKCS#7 паддинг
```

*cbc_encrypt() / cbc_decrypt()*

Шифрование/дешифрование в режиме CBC.

Особенности:
```

Требует вектор инициализации (IV)

Использует PKCS#7 паддинг
```

*cfb_encrypt() / cfb_decrypt()*

Шифрование/дешифрование в режиме CFB.

Особенности:
```

Поточный режим
```

*ofb_encrypt() / ofb_decrypt()*

Шифрование/дешифрование в режиме OFB.

Особенности:
```

Поточный режим
```

ctr_encrypt() / ctr_decrypt()

Шифрование/дешифрование в режиме CTR.

Особенности:
```

Поточный режим
```

*Вспомогательные функции:*

*generate_random_iv()*

Генерирует случайный вектор инициализации.

Параметры:
```

iv (BYTE*) – буфер для записи IV (16 байт)
```

Пример:

```c

BYTE iv[IV_SIZE];

generate_random_iv(iv);
```

*requires_padding()*

Определяет, требуется ли паддинг для данного режима.

Параметры:
```

mode (cipher_mode_t) – режим шифрования
```

Возвращает:
```

int – 1 если требуется паддинг, 0 в противном случае
```

Пример:

```c

if (requires_padding(MODE_CBC)) {

printf("CBC mode requires padding\n");

}
```

*xor_blocks()*

Выполняет операцию XOR между двумя блоками.

Параметры:
```

a (const BYTE*) – первый блок

b (const BYTE*) – второй блок

result (BYTE*) – буфер для результата

len (size_t) – длина блоков
```

Пример:

```c

BYTE a[16], b[16], result[16];

xor_blocks(a, b, result, 16);
```

6. cryptocore.gcm

Структуры:

*gcm_ctx_t*

Контекст для операций GCM.

```c

typedef struct {

BYTE key[16];

BYTE H[16];

BYTE H_table[GCM_TABLE_SIZE][16];

BYTE J0[16];

BYTE nonce[12];

int nonce_provided;

} gcm_ctx_t;
```

Основные функции:

*gcm_encrypt_full()*

Выполняет полное шифрование GCM с генерацией тега аутентификации.

Параметры:
```
key (const BYTE*) – 128-битный ключ AES

plaintext (const BYTE*) – открытый текст

plaintext_len (size_t) – длина открытого текста

aad (const BYTE*) – дополнительные аутентифицируемые данные

aad_len (size_t) – длина AAD

output (BYTE**) – указатель на указатель для выходных данных

output_len (size_t*) – указатель для длины выходных данных
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

Формат вывода:

```text

[nonce 12 bytes][ciphertext][tag 16 bytes]
```

*gcm_decrypt_full()*

Выполняет полное дешифрование GCM с проверкой тега аутентификации.

Параметры:
```
key (const BYTE*) – 128-битный ключ AES

input (const BYTE*) – входные данные (nonce + ciphertext + tag)

input_len (size_t) – длина входных данных

aad (const BYTE*) – дополнительные аутентифицируемые данные

aad_len (size_t) – длина AAD

output (BYTE**) – указатель на указатель для выходных данных

output_len (size_t*) – указатель для длины выходных данных
```

Возвращает:
```
int – 1 при успешной аутентификации и дешифровании, 0 при ошибке аутентификации
```

Вызывает:
```
GCM_AUTH_FAILED – если тег аутентификации неверен или AAD не совпадает
```

Соображения безопасности:
```
Аутентификация выполняется перед дешифрованием

При сбое аутентификации не производится дешифрование
```

7. cryptocore.etm

Структуры:

*etm_ctx_t*

Контекст для операций Encrypt-then-MAC.

```c
typedef struct {

BYTE enc_key[AES_128_KEY_SIZE];

BYTE mac_key[HMAC_DIGEST_SIZE];

cipher_mode_t enc_mode;

} etm_ctx_t;
```

Основные функции:

*encrypt_then_mac()*

Выполняет шифрование, затем вычисляет HMAC.

Параметры:
```
enc_mode (cipher_mode_t) – режим шифрования (CBC, CFB, OFB, CTR)

key (const BYTE*) – мастер-ключ

key_len (size_t) – длина ключа (должна быть ≥ 32 байта для разделения)

plaintext (const BYTE*) – открытый текст

plaintext_len (size_t) – длина открытого текста

aad (const BYTE*) – дополнительные аутентифицируемые данные

aad_len (size_t) – длина AAD

output (BYTE**) – указатель на указатель для выходных данных

output_len (size_t*) – указатель для длины выходных данных
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

Формат вывода:

```text
[ciphertext][HMAC 32 bytes]
```

*decrypt_then_verify()*

Выполняет проверку HMAC, затем дешифрование.

Параметры:
```
enc_mode (cipher_mode_t) – режим шифрования

key (const BYTE*) – мастер-ключ

key_len (size_t) – длина ключа

input (const BYTE*) – входные данные (ciphertext + HMAC)

input_len (size_t) – длина входных данных

aad (const BYTE*) – дополнительные аутентифицируемые данные

aad_len (size_t) – длина AAD

output (BYTE**) – указатель на указатель для выходных данных

output_len (`size_t*) – указатель для длины выходных данных
```

Возвращает:
```
int – 1 при успешной аутентификации и дешифровании, 0 при ошибке
```

Соображения безопасности:
```
HMAC вычисляется над AAD и ciphertext

Проверка аутентификации выполняется перед дешифрованием
```

8. cryptocore.hash

*SHA-256*

sha256_ctx_t

Контекст для инкрементального вычисления SHA-256.

```c

typedef struct {

uint32_t state[8];

uint64_t count;

BYTE buffer[SHA256_BLOCK_SIZE];

} sha256_ctx_t;
```

*sha256_init()*

Инициализирует контекст SHA-256.

Параметры:
```
ctx (sha256_ctx_t*) – указатель на контекст
```

Пример:
```c
sha256_ctx_t ctx;

sha256_init(&ctx);
```

*sha256_update()*

Добавляет данные для хэширования.

Параметры:
```
ctx (sha256_ctx_t*) – указатель на контекст

data (const BYTE*) – данные для добавления

len (size_t) – длина данных
```

Пример:
```c
sha256_update(&ctx, data, data_len);
```

*sha256_final()*

Завершает вычисление хэша и сохраняет результат.

Параметры:
```
ctx (sha256_ctx_t*) – указатель на контекст

digest (BYTE*) – буфер для записи хэша (32 байта)
```

Пример:
```c
BYTE hash[32];

sha256_final(&ctx, hash);
```

*sha256_hash()*

Вычисляет SHA-256 хэш за одну операцию.

Параметры:
```
data (const BYTE*) – данные для хэширования

len (size_t) – длина данных

digest (BYTE*) – буфер для записи хэша (32 байта)
```

Пример:
```c
BYTE hash[32];

sha256_hash(data, data_len, hash);
```

*sha256_file_hash()*

Вычисляет SHA-256 хэш файла с обработкой по чанкам.

Параметры:
```
filename (const char*) – путь к файлу

digest (BYTE*) – буфер для записи хэша (32 байта)

chunk_size (size_t) – размер чанка для обработки
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```
Пример:
```c
BYTE file\_hash[32];

if (sha256_file_hash("large_file.iso", file\_hash, 8192)) {

printf("File hash computed successfully\n");

}
```

*SHA3-256*

*sha3_256_hash()*

Вычисляет SHA3-256 хэш.

Параметры:
```
data (const BYTE*) – данные для хэширования

len (size_t) – длина данных

digest (BYTE*) – буфер для записи хэша (32 байта)
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

Пример:
```c
BYTE hash[32];

if (sha3_256_hash(data, data_len, hash)) {

printf("SHA3-256 hash computed\n");

}
```

9. cryptocore.mac

*HMAC-SHA256*

hmac_ctx_t

Контекст для инкрементального вычисления HMAC.
```c
typedef struct {

sha256_ctx_t hash_ctx;

BYTE key[HMAC_BLOCK_SIZE];

BYTE o_key_pad[HMAC_BLOCK_SIZE];

BYTE i_key_pad[HMAC_BLOCK_SIZE];

} hmac_ctx_t;
```

*hmac_init()*

Инициализирует контекст HMAC с ключом.

Параметры:
```
ctx (hmac_ctx_t*) – указатель на контекст

key (const BYTE*) – ключ HMAC

key_len (size\t) – длина ключа
```

Пример:
```c
hmac_ctx_t ctx;

BYTE key[] = {0x01, 0x02, 0x03};

hmac_init(&ctx, key, sizeof(key));
```

*hmac_update()*

Добавляет данные для вычисления HMAC.

Параметры:
```
ctx (hmac_ctx_t*) – указатель на контекст

data (const BYTE\*) – данные для добавления

data_len (size_t) – длина данных
```

*hmac_final()*

Завершает вычисление HMAC и сохраняет результат.

Параметры:
```
ctx (hmac_ctx_t*) – указатель на контекст

digest (BYTE*) – буфер для записи HMAC (32 байта)
```

*hmac_compute()*

Вычисляет HMAC-SHA256 за одну операцию.

Параметры:
```
key (const BYTE*) – ключ HMAC

key_len (size_t) – длина ключа

data (const BYTE*) – данные для HMAC

data_len (size_t) – длина данных

digest (BYTE*) – буфер для записи HMAC (32 байта)
```

Пример:
```c
BYTE hmac[32];

hmac_compute(key, key_len, data, data_len, hmac);
```

*hmac_verify()*

Проверяет HMAC.

Параметры:
```
key (const BYTE*) – ключ HMAC

key_len (size_t) – длина ключа

data (const BYTE*) – данные для проверки

data_len (size_t) – длина данных

expected_digest (const BYTE*) – ожидаемый HMAC
```

Возвращает:
```
int – 1 если HMAC совпадает, 0 если нет
```

Пример:
```c
if (hmac_verify(key, key_len, data, data_len, expected_hmac)) {

printf("HMAC verification successful\n");

}
```

*hmac_file_compute()*

Вычисляет HMAC для файла с обработкой по чанкам.

Параметры:
```
key (const BYTE*) – ключ HMAC

key_len (size_t) – длина ключа

filename (const char*) – путь к файлу

digest (BYTE*) – буфер для записи HMAC (32 байта)

chunk_size (size_t) – размер чанка
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

*AES-CMAC*

*cmac_compute()*

Вычисляет AES-CMAC.

Параметры:
```
key (const BYTE*) – 128-битный ключ AES

data (const BYTE*) – данные для CMAC

data_len (size_t) – длина данных

digest (BYTE*) – буфер для записи CMAC (16 байт)
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

Пример:
```c
BYTE cmac[16];

if (cmac_compute(aes_key, data, data_len, cmac)) {

printf("CMAC computed successfully\n");

}
```

*cmac_verify()*

Проверяет AES-CMAC.

Параметры:
```
key (const BYTE*) – 128-битный ключ AES

data (const BYTE*) – данные для проверки

data_len (size_t) – длина данных

expected_digest (const BYTE*) – ожидаемый CMAC
```

Возвращает:
```
int – 1 если CMAC совпадает, 0 если нет
```

*cmac_file_compute()*

Вычисляет AES-CMAC для файла.

Параметры:
```
key (const BYTE*) – 128-битный ключ AES

filename (const char*) – путь к файлу

digest (BYTE*) – буфер для записи CMAC (16 байт)
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

10. cryptocore.kdf

*PBKDF2-HMAC-SHA256*

*pbkdf2_hmac_sha256()*

Выполняет вывод ключа с использованием PBKDF2 с HMAC-SHA256.

Параметры:
```
password (const BYTE*) – пароль

password_len (size_t) – длина пароля

salt (const BYTE*) – соль

salt_len (size_t) – длина соли

iterations (unsigned int) – количество итераций

dklen (size_t) – длина производного ключа

derived_key (BYTE*) – буфер для записи производного ключа
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

Пример:
```c
BYTE derived_key[32];

BYTE salt[16] = {0x01, 0x02, 0x03};

const char *password = "MySecretPassword";

if (pbkdf2_hmac_sha256((BYTE*)password, strlen(password),

salt, sizeof(salt),

100000, 32, derived_key)) {

printf("Key derived successfully\n");

}
```

Соображения безопасности:
```
Рекомендуемое количество итераций: ≥ 100,000

Используйте уникальную соль для каждого ключа

Очищайте чувствительные данные после использования
```

*HKDF*

*derive_key_from_master()*

Выполняет вывод ключа с использованием HKDF.

Параметры:
```
master_key (const BYTE*) – мастер-ключ

master_key_len (size_t) – длина мастер-ключа

context (const char*) – контекстная строка

derived_key_len (size_t) – длина производного ключа

derived_key (BYTE*) – буфер для записи производного ключа
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

Пример:
```c
BYTE master_key[32];

BYTE derived_key[32];

const char *context = "encryption_key";

if (derive_key_from_master(master_key, sizeof(master_key),

context, 32, derived_key)) {

printf("HKDF key derived successfully\n");

}
```

11. cryptocore.testing

Функции запуска тестов:

*run_all_key_tests()*

Запускает все тесты генерации ключей и CSPRNG.

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*run_hash_tests()*

Запускает все тесты хэш-функций (SHA-256, SHA3-256).

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*run_all_mac_tests()*

Запускает все тесты MAC функций (HMAC, CMAC).

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*run_aead_tests()*

Запускает все тесты AEAD функций (GCM).

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*run_all_kdf_tests()*

Запускает все тесты KDF функций (PBKDF2, HKDF).

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*main_unit_tests()*

Запускает все модульные тесты.

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*run_all_vectors_tests()*

Запускает все known-answer тесты (векторы NIST/RFC).

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*run_all_integration_tests()*

Запускает все интеграционные тесты CLI.

Возвращает:
```
int – 1 если все тесты пройдены, 0 если есть ошибки
```

*generate_nist_test_file()*

Генерирует тестовый файл для проверок NIST.

Параметры:
```
filename (const char*) – имя файла

size_bytes (size_t) – размер файла в байтах
```

Возвращает:
```
int – 1 при успехе, 0 при ошибке
```

12. Соображения безопасности

*Критические требования*

Генерация случайных чисел:
```
Все случайные значения генерируются с использованием RAND_bytes() OpenSSL

Автоматическая генерация ключей и IV при необходимости

Проверка слабых ключей
```
Управление памятью:
```
Чувствительные данные очищаются после использования

Проверка выделения памяти

Освобождение ресурсов при ошибках
```
Аутентификация:
```
В GCM: аутентификация перед дешифрованием

В ETM: проверка HMAC перед дешифрованием

Отказ в выводе данных при сбое аутентификации
```
Валидация входных данных:
```
Проверка шестнадцатеричных строк

Валидация длин ключей и параметров

Проверка размеров файлов
```
