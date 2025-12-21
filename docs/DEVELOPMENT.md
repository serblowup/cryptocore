**Введение**

*Консольная утилита для шифрования и дешифрования файлов с использованием AES-128 в режимах ECB, CBC, CFB, OFB, CTR, GCM. Собственная реализация хеш-функций SHA-256 и SHA3-256, имитовставок HMAC и AES-CMAC. Шифрование/дешифрование с дополнительными аутентифицируемыми данными (AAD) для режимов CBC, CFB, OFB, CTR.*

**Сборка**:
```bash
# Сборка проекта
make all 
# Запуск всех тестов
make test-all
# Очистка
make clean
```

**Структура проекта после сборки**:
```
cryptocore/
├── build/
│   ├── src/
│   └── tests/
├── include/
├── src/
│   ├── modes/
│   ├── aead/
│   ├── hash/
│   ├── mac/
│   └── kdf/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── vectors/ 
├── docs/ 
├── Makefile 
├── README.md
└── CHANGELOG.md
```
