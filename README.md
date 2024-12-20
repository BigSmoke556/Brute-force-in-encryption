# Brute-force-in-encryption
# Decryptor Toolkit - Ferramentas para Descriptografia e Hashing

Este repositório contém um conjunto de funções desenvolvidas para explorar, descriptografar e verificar diferentes tipos de algoritmos de criptografia, além de gerar hashes utilizando o módulo `hashlib` e outras bibliotecas de Python.

## Aviso

Este código foi desenvolvido com fins educacionais e não deve ser utilizado para atividades ilegais ou não autorizadas. O autor não se responsabiliza pelo uso indevido deste software.


O objetivo principal é fornecer uma abordagem unificada para testar e manipular diversos métodos de criptografia e codificação. É ideal para estudos em segurança da informação e cibersegurança.

## Funcionalidades

O código implementa suporte aos seguintes métodos de criptografia e hashing:

- **AES**: Descriptografia com modo EAX usando a biblioteca PyCryptodome.
- **DES**: Descriptografia com modo EAX usando a biblioteca PyCryptodome.
- **Blowfish**: Descriptografia com modo EAX usando a biblioteca PyCryptodome.
- **Fernet**: Descriptografia usando a biblioteca cryptography.
- **bcrypt**: Verificação de hashes utilizando a biblioteca bcrypt.
- **Base64**: Decodificação de textos codificados.
- **Cifra de César**: Decodificação com tentativa de todas as rotações possíveis (brute force).
- **Cifra de Vigenère**: Decodificação com palavras-chave pré-definidas.
- **Geração de hashes**: Geração de hash utilizando o algoritmo SHA-256 ou outros suportados pelo módulo `hashlib`.

## Estrutura do Código

### Funções de Descriptografia:

- **decrypt_aes**: Para descriptografar textos cifrados com AES.
- **decrypt_des**: Para descriptografar textos cifrados com DES.
- **decrypt_blowfish**: Para descriptografar textos cifrados com Blowfish.
- **decrypt_fernet**: Para descriptografar textos cifrados com Fernet.
- **decrypt_bcrypt**: Para verificar um hash bcrypt.

### Codificações Simples:

- **try_base64_decode**: Para decodificar textos em Base64.
- **try_caesar_cipher**: Para decodificar textos usando a cifra de César.
- **try_vigenere_cipher**: Para decodificar textos usando a cifra de Vigenère com palavras-chave.

### Funções de Hash:

- **decrypt_hash**: Gera hashes com algoritmos de hash padrão, como SHA-256.

### Função Principal:

- **try_all_methods**: Testa vários métodos de descriptografia no texto de entrada e exibe os resultados no console.

## Bibliotecas Utilizadas

As seguintes bibliotecas Python são utilizadas neste projeto:

- `hashlib` (padrão do Python): Para gerar hashes.
- `PyCryptodome`: Para implementar AES, DES e Blowfish.
- `cryptography`: Para manipular criptografia Fernet.
- `bcrypt`: Para verificação de hashes bcrypt.
- `base64`: Para manipulação de textos codificados em Base64.
- `caesarcipher`: Para manipular a cifra de César.
- `itertools`: Para auxiliar na implementação da cifra de Vigenère.

## Exemplo de Uso

O código inclui um exemplo funcional, onde um texto cifrado é processado com todas as funções de descriptografia disponíveis. Basta substituir as variáveis `text` e `key` pelo texto cifrado e chave apropriados.

```python
text = b"c126kPtkE9xkpd08ojpDDg"  # Texto cifrado de exemplo
key = b"suachave"  # Chave para AES, DES e Blowfish
try_all_methods(text, key)


