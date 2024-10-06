<p align="center"><a href="https://www.localzet.com" target="_blank">
  <img src="https://static.zorin.space/media/logos/ZorinProjectsSP.svg" width="400">
</a></p>

<p align="center">
  <a href="https://packagist.org/packages/localzet/lwt">
  <img src="https://img.shields.io/packagist/dt/localzet/lwt?label=%D0%A1%D0%BA%D0%B0%D1%87%D0%B8%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F" alt="Скачивания">
</a>
  <a href="https://github.com/localzet/lwt">
  <img src="https://img.shields.io/github/commit-activity/t/localzet/lwt?label=%D0%9A%D0%BE%D0%BC%D0%BC%D0%B8%D1%82%D1%8B" alt="Коммиты">
</a>
  <a href="https://packagist.org/packages/localzet/lwt">
  <img src="https://img.shields.io/packagist/v/localzet/lwt?label=%D0%92%D0%B5%D1%80%D1%81%D0%B8%D1%8F" alt="Версия">
</a>
  <a href="https://packagist.org/packages/localzet/lwt">
  <img src="https://img.shields.io/packagist/dependency-v/localzet/lwt/php?label=PHP" alt="Версия PHP">
</a>
  <a href="https://github.com/localzet/lwt">
  <img src="https://img.shields.io/github/license/localzet/lwt?label=%D0%9B%D0%B8%D1%86%D0%B5%D0%BD%D0%B7%D0%B8%D1%8F" alt="Лицензия">
</a>
</p>

# LWT - Localzet Web Tokens <i>(JWT-based)</i>

Класс `LWT` предоставляет методы для кодирования и декодирования LWT-токенов. Он использует алгоритмы шифрования AES и RSA для шифрования данных в токене.

## Использование

### Кодирование LWT-токена

Чтобы кодировать LWT-токен, используйте метод `encode()` класса `LWT`. Этот метод принимает данные, закрытый ключ и алгоритм шифрования (по умолчанию `ES512`) в качестве аргументов. 

>Если закрытый ключ и алгоритм шифрования не указаны, используются значения, определенные в классе.

```php
$data = ['username' => 'localzet', 'email' => 'creator@localzet.com'];
$tokenPrivateKey = '...'; // Закрытый ключ для шифрования токена (рекомендую ECDSA)
$tokenEncryption = 'HS256'; // Алгоритм шифрования (по умолчанию ES512)

$encodedToken = LWT::encode($data, $tokenPrivateKey, $tokenEncryption);
```

### Декодирование LWT-токена

Чтобы декодировать LWT-токен и получить расшифрованные данные, используйте метод `decode()` класса `LWT`. Этот метод принимает закодированный токен, публичный ключ и алгоритм шифрования в качестве аргументов. 

>Если публичный ключ и алгоритм шифрования не указаны, используются значения, определенные в классе.

```php
$encodedToken = '...'; // Закодированный LWT-токен
$tokenPublicKey = '...'; // Публичный ключ для шифрования токена (рекомендую ECDSA)
$tokenEncryption = 'HS256'; // Алгоритм шифрования (по умолчанию ES512)

$decodedData = LWT::decode($encodedToken, $tokenPublicKey, $tokenEncryption);
```

### Кодирование данных в LWT-токене

Чтобы закодировать данные в LWT-токене и дополнительно обезопасить их, используйте методы `encode()` и `decode()` класса `LWT` с дополнительными аргументами. 
Эти методы принимают дополнительные ключи для шифрования данных в полезной нагрузке комбинацией ассиметричного (RSA) и симметричного (AES-256-CBC) алгоритмов.

>Если дополнительные ключи для шифрования данных не указаны, данные загружаются в полезную нагрузку в неизменном виде.

```php
$encodedToken = '...'; // Закодированный LWT-токен
$tokenPublicKey = '...'; // Публичный ключ для шифрования токена (рекомендую ECDSA)
$tokenEncryption = 'HS256'; // Алгоритм шифрования (по умолчанию ES512)

$decodedData = LWT::decode($encodedToken, $tokenPublicKey, $tokenEncryption);
```

## Настройка

Класс `LWT` имеет несколько статических свойств и констант, которые можно настроить для изменения поведения кодирования и декодирования токенов.

### Настройка JWT-совместимого алгоритма шифрования LWT-токена

Чтобы изменить алгоритм шифрования для сигнатуры, измените значение константы `LWT_ENCRYPTION`.

>Возможные значения: \
> **HMAC-based**: HS256, HS384, HS512 \
> **RSA-based**: RS256, RS384, RS512 \
> **ECDSA-based**: ES256, ES384, ES512
```php
// Изменение алгоритма шифрования для сигнатуры LWT-токена (рекомендую ES512)
LWT::LWT_ENCRYPTION = 'ES512';
```

### Настройка закрытого и публичного ключей LWT-токена

Чтобы изменить закрытый или публичный ключи для кодирования или декодирования LWT-токена, измените значения статических свойств `$LWT_PRIVATE_KEY` и `$LWT_PUBLIC_KEY` соответственно.

```php
// Изменение закрытого ключа для кодирования LWT-токена
LWT::$LWT_PRIVATE_KEY = '...'; // Закрытый ключ в формате PEM (рекомендую ECDSA)

// Изменение публичного ключа для декодирования LWT-токена
LWT::$LWT_PUBLIC_KEY = '...'; // Публичный ключ в формате PEM (рекомендую ECDSA)
```

### Настройка закрытого и публичного ключей данных

Чтобы изменить закрытый или публичный ключи для шифрования или расшифровки данных, измените значения статических свойств `$DATA_PRIVATE_KEY` и `$DATA_PUBLIC_KEY` соответственно.

```php
// Изменение закрытого ключа для шифрования данных
LWT::$DATA_PRIVATE_KEY = '...'; // Закрытый ключ RSA

// Изменение публичного ключа для расшифровки данных
LWT::$DATA_PUBLIC_KEY = '...'; // Публичный ключ RSA
```
