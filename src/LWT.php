<?php

declare(strict_types=1);

namespace localzet;

use DomainException;
use RuntimeException;
use UnexpectedValueException;
use function strlen;

final class LWT
{
// Определение констант для типа, шифрования и алгоритма LWT-токена
    private const LWT_TYPE = 'LWTv3'; // Тип LWT-токена
    private const LWT_ALGORITHM = 'LZX:{D-SYM}+{D-ASYM}*(HMAC/RSA/ECDSA)-SHA(256/384/512)'; // Алгоритм шифрования для данных LWT-токена
    const LWT_ENCRYPTION = 'ES512'; // Алгоритм шифрования для сигнатуры LWT-токена

// Определение статических свойств для закрытого и публичного ключей LWT-токена
    static ?string $LWT_PRIVATE_KEY = null; // Закрытый ключ в формате PEM (ECDSA)
    static ?string $LWT_PUBLIC_KEY = null; // Публичный ключ в формате PEM (ECDSA)

// Определение констант для симметричного и асимметричного шифрования данных
    private const DATA_SYMMETRIC_ENCRYPTION = 'AES-256-CBC'; // Алгоритм симметричного шифрования данных
    private const DATA_ASYMMETRIC_ENCRYPTION = 'RSA'; // Алгоритм асимметричного шифрования данных

// Определение статических свойств для закрытого и публичного ключей данных
    static ?string $DATA_PRIVATE_KEY = null; // Закрытый ключ в формате PEM (RSA)
    static ?string $DATA_PUBLIC_KEY = null; // Публичный ключ в формате PEM (RSA)

    private const LWT_TOKEN_SEGMENTS_COUNT = 3;
    private const AES_KEY_LENGTH_OFFSET = 4;
    private const AES_KEY_LENGTH = 32;
    private const HASH_RAW_OUTPUT = true;
    private const OPENSSL_VERIFY_SUCCESS = 1;
    private const BASE64_GROUP_SIZE = 4;
    private const JSON_MAX_DEPTH = 512;
    private const STRINGS_MATCH = 0;
    private const MBSTRING_ENCODING = '8bit';

    /**
     * @return string
     */
    private static function generateKID(): string
    {
        $ENCRYPTION = match (self::LWT_ENCRYPTION) {
            'HS256', 'HS384', 'HS512' => 'HMAC',
            'RS256', 'RS384', 'RS512' => 'RSA',
            'ES256', 'ES384', 'ES512' => 'ECDSA',
        };

        $SHA = match (self::LWT_ENCRYPTION) {
            'HS256', 'RS256', 'ES256' => '256',
            'HS384', 'RS384', 'ES384' => '384',
            'HS512', 'RS512', 'ES512' => '512',
        };

        return str_replace(
            ['{D-SYM}', '{D-ASYM}', '(HMAC/RSA/ECDSA)', '(256/384/512)'],
            [self::DATA_SYMMETRIC_ENCRYPTION, self::DATA_ASYMMETRIC_ENCRYPTION, $ENCRYPTION, $SHA],
            self::LWT_ALGORITHM
        );
    }


    /**
     * Кодирует данные в LWT-токен.
     *
     * Эта функция кодирует данные в LWT-токен и возвращает полученную строку. Она принимает
     * данные, закрытый ключ, публичный ключ и алгоритм шифрования в качестве аргументов.
     * Если эти аргументы не указаны, используются значения по умолчанию, определенные в классе.
     *
     * @param mixed $lwtTokenData Данные для кодирования в LWT-токен.
     * @param string|null $ecdsaPrivateKey Закрытый ключ в формате PEM (ECDSA).
     * @param string|null $tokenEncryption Алгоритм шифрования (например, 'HS256', 'RS256').
     * @param string|null $rsaPublicKey Публичный ключ в формате PEM (RSA).
     *
     * @return string Возвращает строку, представляющую закодированный LWT-токен.
     */
    public static function encode(
        mixed  $lwtTokenData,
        string $ecdsaPrivateKey = null,
        string $tokenEncryption = null,
        string $rsaPublicKey = null,
    ): string
    {
        // Генерируем сегмент заголовка токена
        $headerSegment = self::generateHeaderSegment();
        // Генерируем сегмент полезной нагрузки токена
        $payloadSegment = self::generatePayloadSegment($lwtTokenData, $rsaPublicKey);
        // Генерируем сигнатуру токена
        $signatureSegment = self::generateSignature($headerSegment, $payloadSegment, $ecdsaPrivateKey, $tokenEncryption);

        // Возвращаем закодированный токен
        return "$headerSegment.$payloadSegment.$signatureSegment";
    }


    /**
     * Декодирует LWT-токен.
     *
     * Эта функция декодирует LWT-токен и возвращает расшифрованные данные. Она принимает
     * закодированный токен, публичный ключ, закрытый ключ и алгоритм шифрования в качестве аргументов.
     * Если эти аргументы не указаны, используются значения по умолчанию, определенные в классе.
     *
     * @param string $encodedToken Закодированный LWT-токен.
     * @param string|null $ecdsaPublicKey Публичный ключ в формате PEM (ECDSA).
     * @param string|null $tokenEncryption Алгоритм шифрования (например, 'HS256', 'RS256').
     * @param string|null $rsaPrivateKey Закрытый ключ в формате PEM (RSA).
     *
     * @return mixed Возвращает расшифрованные данные из токена.
     *
     * @throws UnexpectedValueException|RuntimeException Если токен имеет неверное количество сегментов.
     */
    public static function decode(
        string $encodedToken,
        string $ecdsaPublicKey = null,
        string $tokenEncryption = null,
        string $rsaPrivateKey = null,
    ): mixed
    {
        // Разбиваем токен на сегменты
        $segments = explode('.', $encodedToken);
        if (count($segments) !== self::LWT_TOKEN_SEGMENTS_COUNT) {
            // Если токен имеет неверное количество сегментов, выбрасываем исключение
            throw new UnexpectedValueException('Неверное кол-во сегментов');
        }

        // Извлекаем сегменты заголовка, тела и криптографической подписи
        list($headerSegment, $payloadSegment, $signatureSegment) = $segments;

        // Проверяем сегмент заголовка
        self::verifyHeaderSegment($headerSegment);
        // Проверяем сегмент полезной нагрузки и извлекаем расшифрованные данные
        $payload = self::verifyPayloadSegment($payloadSegment, $rsaPrivateKey);
        // Проверяем сигнатуру токена
        self::verifySignature($headerSegment, $payloadSegment, $signatureSegment, $ecdsaPublicKey, $tokenEncryption);

        // Возвращаем расшифрованные данные
        return $payload;
    }


    /**
     * Генерирует сегмент заголовка LWT-токена.
     *
     * Эта функция генерирует сегмент заголовка LWT-токена, используя значения по умолчанию
     * для типа токена и алгоритма шифрования, которые определены в классе.
     *
     * @return string Возвращает сегмент заголовка токена в формате base64url.
     */
    private static function generateHeaderSegment(): string
    {
        // Генерируем заголовок токена
        $header = [
            'typ' => self::LWT_TYPE,
            'alg' => self::LWT_ENCRYPTION,
            'kid' => self::generateKID()
        ];
        // Кодируем заголовок в формате JSON
        $headerJson = self::jsonEncode($header);

        // Кодируем заголовок в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($headerJson);
    }

    /**
     * Проверяет сегмент заголовка LWT-токена.
     *
     * Эта функция проверяет сегмент заголовка LWT-токена. Она проверяет, что тип токена и алгоритм
     * шифрования соответствуют значениям по умолчанию, определенным в классе. Если проверка не пройдена,
     * функция выбрасывает исключение UnexpectedValueException.
     *
     * @param string $lwtTokenHeaderSegment Сегмент заголовка LWT-токена.
     *
     * @throws UnexpectedValueException Если тип токена или алгоритм шифрования не соответствуют значениям по умолчанию.
     */
    private static function verifyHeaderSegment(string $lwtTokenHeaderSegment): void
    {
        // Декодируем сегмент заголовка из формата base64url
        $headerJson = self::base64UrlDecode($lwtTokenHeaderSegment);
        // Декодируем заголовок из формата JSON
        $header = self::jsonDecode($headerJson);

        // Проверяем, что тип токена и алгоритм шифрования соответствуют значениям по умолчанию
        if (!$header ||
            $header['typ'] !== self::LWT_TYPE ||
            $header['alg'] !== self::LWT_ENCRYPTION ||
            $header['kid'] !== self::generateKID()
        ) {
            // Если проверка не пройдена, выбрасываем исключение
            throw new UnexpectedValueException('Ошибка шифрования заголовка');
        }
    }


    /**
     * Генерирует сегмент полезной нагрузки LWT-токена.
     *
     * Эта функция генерирует сегмент полезной нагрузки LWT-токена, используя данные и публичный ключ.
     * Она кодирует данные в формате JSON, шифрует их с помощью алгоритмов AES и RSA, и возвращает
     * полученную строку в формате base64url.
     *
     * @param mixed $lwtTokenData Данные для кодирования в LWT-токен.
     * @param string|null $rsaPublicKey Публичный ключ в формате PEM (RSA).
     *
     * @return string Возвращает сегмент полезной нагрузки токена в формате base64url.
     *
     * @see https://tools.ietf.org/html/rfc7519
     * @see https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php
     * @see https://www.php.net/manual/en/function.openssl-public-encrypt.php
     * @see https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     */
    private static function generatePayloadSegment(
        mixed  $lwtTokenData,
        string $rsaPublicKey = null,
    ): string
    {
        // Кодируем данные в формате JSON
        $payloadData = self::jsonEncode($lwtTokenData);

        // Проверяем, указан ли публичный ключ или установлен ли он по умолчанию
        if ($rsaPublicKey || self::$DATA_PUBLIC_KEY) {
            // Генерируем временный ключ AES
            $aesKey = openssl_random_pseudo_bytes(self::AES_KEY_LENGTH);

            // Зашифровываем ключ AES с помощью шифрования RSA
            openssl_public_encrypt($aesKey, $encryptedAesKey, ($rsaPublicKey ?? self::$DATA_PUBLIC_KEY));

            // Генерируем вектор инициализации для алгоритма AES
            $initializationVectorLength = openssl_cipher_iv_length(self::DATA_SYMMETRIC_ENCRYPTION);
            $initializationVector = openssl_random_pseudo_bytes($initializationVectorLength);

            // Шифруем данные с помощью алгоритма AES
            $encryptedPayloadData = openssl_encrypt($payloadData, self::DATA_SYMMETRIC_ENCRYPTION, $aesKey, 0, $initializationVector);

            // Формируем полезную нагрузку токена, добавляя информацию о длине ключа и сам ключ AES,
            // а также вектор инициализации и зашифрованные данные
            $payloadData = pack('N', self::AES_KEY_LENGTH_OFFSET + strlen($encryptedAesKey)) . $encryptedAesKey . $initializationVector . $encryptedPayloadData;
        }

        // Кодируем полезную нагрузку токена в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($payloadData);
    }

    /**
     * Проверяет сегмент полезной нагрузки LWT-токена.
     *
     * Эта функция проверяет сегмент полезной нагрузки LWT-токена. Она расшифровывает данные,
     * используя закрытый ключ и алгоритмы AES и RSA, и возвращает расшифрованные данные. Если при
     * расшифровке произошла ошибка, функция выбрасывает исключение RuntimeException.
     *
     * @param string $lwtTokenPayloadSegment Сегмент полезной нагрузки LWT-токена.
     * @param string|null $rsaPrivateKey Закрытый ключ в формате PEM (RSA).
     *
     * @return mixed Возвращает расшифрованные данные из токена.
     *
     * @throws RuntimeException Если при расшифровке произошла ошибка.
     *
     * @see https://www.php.net/manual/en/function.unpack.php
     * @see https://www.php.net/manual/en/function.substr.php
     * @see https://www.php.net/manual/en/function.openssl-private-decrypt.php
     * @see https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     */
    private static function verifyPayloadSegment(
        string  $lwtTokenPayloadSegment,
        ?string $rsaPrivateKey
    ): mixed
    {
        // Декодируем тело из base64url
        $payloadData = self::base64UrlDecode($lwtTokenPayloadSegment);

        if ($rsaPrivateKey || self::$DATA_PRIVATE_KEY) {

            // Извлекаем длину зашифрованного ключа AES из данных
            $encryptedAesKeyLength = (int)@unpack('Ntotal_length', $payloadData)['total_length'] - self::AES_KEY_LENGTH_OFFSET;

            // Извлекаем зашифрованный ключ AES из данных
            $encryptedAesKey = substr($payloadData, self::AES_KEY_LENGTH_OFFSET, $encryptedAesKeyLength);

            // Удаляем информацию о длине ключа и сам ключ из данных
            $encryptedPayload = substr($payloadData, self::AES_KEY_LENGTH_OFFSET + $encryptedAesKeyLength);

            // Расшифровываем ключ AES с помощью шифрования RSA
            openssl_private_decrypt($encryptedAesKey, $aesKey, ($rsaPrivateKey ?? self::$DATA_PRIVATE_KEY));

            // Извлекаем вектор инициализации из зашифрованных данных
            $initializationVectorLength = openssl_cipher_iv_length(self::DATA_SYMMETRIC_ENCRYPTION);
            $initializationVector = substr($encryptedPayload, 0, $initializationVectorLength);
            $encryptedPayloadData = substr($encryptedPayload, $initializationVectorLength);

            // Расшифровываем данные с помощью алгоритма AES
            $payloadData = openssl_decrypt($encryptedPayloadData, self::DATA_SYMMETRIC_ENCRYPTION, $aesKey, 0, $initializationVector);
        }

        // Декодируем JSON-представление данных
        $payload = self::jsonDecode($payloadData);
        if (!$payload) {
            // Если при расшифровке произошла ошибка, выбрасываем исключение
            throw new RuntimeException('Ошибка шифрования параметров');
        }

        // Возвращаем расшифрованные данные
        return $payload;
    }

    /**
     * Генерирует сигнатуру для LWT-токена.
     *
     * Эта функция генерирует сигнатуру для LWT-токена, используя алгоритм шифрования,
     * указанный в аргументе $signatureAlgorithm. Если этот аргумент не указан, используется
     * значение по умолчанию, определенное в классе. Функция также принимает закрытый ключ
     * в качестве аргумента $ecdsaPrivateKey. Если этот аргумент не указан, используется
     * значение по умолчанию, определенное в классе.
     *
     * @param string $headerSegment Сегмент заголовка LWT-токена.
     * @param string $payloadSegment Сегмент полезной нагрузки LWT-токена.
     * @param string|null $ecdsaPrivateKey Закрытый ключ в формате PEM (ECDSA).
     * @param string|null $signatureAlgorithm Алгоритм шифрования (например, 'HS256', 'RS256').
     *
     * @return string Возвращает сигнатуру в формате base64url.
     *
     * @see https://www.php.net/manual/en/function.openssl-sign.php
     * @see https://www.php.net/manual/en/function.hash-hmac.php
     */
    private static function generateSignature(string $headerSegment, string $payloadSegment, ?string $ecdsaPrivateKey, ?string $signatureAlgorithm): string
    {
        // Генерируем LWT-совместимую сигнатуру
        $algorithm = $signatureAlgorithm ?? self::LWT_ENCRYPTION;
        $data = "$headerSegment.$payloadSegment";
        $private_key = ($ecdsaPrivateKey ?? self::$LWT_PRIVATE_KEY);

        switch ($algorithm) {
            case 'HS256':   // HMAC-SHA256
                $signature = hash_hmac('SHA256', $data, self::generateHmacKeyFromPrivateKey($private_key), self::HASH_RAW_OUTPUT);
                break;
            case 'HS384':   // HMAC-SHA384
                $signature = hash_hmac('SHA384', $data, self::generateHmacKeyFromPrivateKey($private_key), self::HASH_RAW_OUTPUT);
                break;
            case 'HS512':   // HMAC-SHA512
                $signature = hash_hmac('SHA512', $data, self::generateHmacKeyFromPrivateKey($private_key), self::HASH_RAW_OUTPUT);
                break;

            case 'RS256':   // RSA-SHA256
            case 'ES256':   // ECDSA-SHA256
                openssl_sign($data, $signature, $private_key, OPENSSL_ALGO_SHA256);
                break;
            case 'RS384':   // RSA-SHA384
            case 'ES384':   // ECDSA-SHA384
                openssl_sign($data, $signature, $private_key, OPENSSL_ALGO_SHA384);
                break;
            case 'RS512':   // RSA-SHA512
            case 'ES512':   // ECDSA-SHA512
            default:
                openssl_sign($data, $signature, $private_key, OPENSSL_ALGO_SHA512);
                break;
        }

        // Возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($signature);
    }


    /**
     * Проверяет сигнатуру LWT-токена.
     *
     * Эта функция проверяет сигнатуру LWT-токена, используя алгоритм шифрования,
     * указанный в аргументе $signatureAlgorithm. Если этот аргумент не указан, используется
     * значение по умолчанию, определенное в классе. Функция также принимает публичный ключ
     * в качестве аргумента $ecdsaPublicKey. Если этот аргумент не указан, используется
     * значение по умолчанию, определенное в классе.
     *
     * @param string $headerSegment Сегмент заголовка LWT-токена.
     * @param string $payloadSegment Сегмент полезной нагрузки LWT-токена.
     * @param string $signatureSegment Сегмент сигнатуры LWT-токена.
     * @param string|null $ecdsaPublicKey Публичный ключ в формате PEM (ECDSA).
     * @param string|null $signatureAlgorithm Алгоритм шифрования (например, 'HS256', 'RS256').
     *
     * @see https://www.php.net/manual/en/function.openssl-verify.php
     * @see https://www.php.net/manual/en/function.hash-hmac.php
     */
    private static function verifySignature(string $headerSegment, string $payloadSegment, string $signatureSegment, ?string $ecdsaPublicKey, ?string $signatureAlgorithm): void
    {
        // Проверяем сигнатуру
        $signature = self::base64UrlDecode($signatureSegment);

        $algorithm = $signatureAlgorithm ?? self::LWT_ENCRYPTION;
        $data = "$headerSegment.$payloadSegment";
        $public_key = ($ecdsaPublicKey ?? self::$LWT_PUBLIC_KEY);

        switch ($algorithm) {
            case 'HS256':   // HMAC-SHA256
                $hash = hash_hmac('SHA256', $data, self::generateHmacKeyFromPublicKey($public_key), self::HASH_RAW_OUTPUT);
                if (!self::hashEquals($hash, $signature)) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;
            case 'HS384':   // HMAC-SHA384
                $hash = hash_hmac('SHA384', $data, self::generateHmacKeyFromPublicKey($public_key), self::HASH_RAW_OUTPUT);
                if (!self::hashEquals($hash, $signature)) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;
            case 'HS512':   // HMAC-SHA512
                $hash = hash_hmac('SHA512', $data, self::generateHmacKeyFromPublicKey($public_key), self::HASH_RAW_OUTPUT);
                if (!self::hashEquals($hash, $signature)) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            case 'RS256':   // RSA-SHA256
            case 'ES256':   // ECDSA-SHA256
                if (openssl_verify($data, $signature, $public_key, OPENSSL_ALGO_SHA256) !== self::OPENSSL_VERIFY_SUCCESS) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;
            case 'RS384':   // RSA-SHA384
            case 'ES384':   // ECDSA-SHA384
                if (openssl_verify($data, $signature, $public_key, OPENSSL_ALGO_SHA384) !== self::OPENSSL_VERIFY_SUCCESS) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;
            case 'RS512':   // RSA-SHA512
            case 'ES512':   // ECDSA-SHA512
            default:
                if (openssl_verify($data, $signature, $public_key, OPENSSL_ALGO_SHA512) !== self::OPENSSL_VERIFY_SUCCESS) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;
        }
    }


    /**
     * Генерирует HMAC-ключ из закрытого ключа.
     *
     * Эта функция использует закрытый ключ для генерации HMAC-ключа. Она также использует
     * значения по умолчанию для типа токена, алгоритма шифрования, симметричного и асимметричного
     * методов шифрования, которые определены в классе.
     *
     * @param string $ecdsaPrivateKey Закрытый ключ в формате PEM (ECDSA).
     *
     * @return string Возвращает HMAC-ключ.
     *
     * @see https://www.php.net/manual/en/function.openssl-pkey-get-private.php
     * @see https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     * @see https://www.php.net/manual/en/function.openssl-sign.php
     */
    private static function generateHmacKeyFromPrivateKey(string $ecdsaPrivateKey): string
    {
        // Генерируем предварительный ключ
        $data = self::LWT_TYPE .
            '*' . self::LWT_ENCRYPTION .
            '*' . self::generateKID() .
            '*' . self::DATA_SYMMETRIC_ENCRYPTION .
            '*' . self::DATA_ASYMMETRIC_ENCRYPTION;

        // Получаем информацию о закрытом ключе
        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_private($ecdsaPrivateKey));
        // Извлекаем публичный ключ из информации о закрытом ключе
        $ecdsaPublicKey = $keyDetails['key'];

        // Генерируем криптографическую подпись с использованием публичного ключа и алгоритма SHA-512
        openssl_sign($data, $signature, $ecdsaPublicKey, OPENSSL_ALGO_SHA512);

        return $signature;
    }

    /**
     * Генерирует HMAC-ключ из публичного ключа.
     *
     * Эта функция использует публичный ключ для генерации HMAC-ключа. Она также использует
     * значения по умолчанию для типа токена, алгоритма шифрования, симметричного и асимметричного
     * методов шифрования, которые определены в классе.
     *
     * @param string $ecdsaPublicKey Публичный ключ в формате PEM (ECDSA).
     *
     * @return string Возвращает HMAC-ключ.
     *
     * @see https://www.php.net/manual/en/function.openssl-sign.php
     */
    private static function generateHmacKeyFromPublicKey(string $ecdsaPublicKey): string
    {
        // Генерируем предварительный ключ
        $data = self::LWT_TYPE .
            '*' . self::LWT_ENCRYPTION .
            '*' . self::generateKID() .
            '*' . self::DATA_SYMMETRIC_ENCRYPTION .
            '*' . self::DATA_ASYMMETRIC_ENCRYPTION;

        // Генерируем криптографическую подпись с использованием публичного ключа и алгоритма SHA-512
        openssl_sign($data, $signature, $ecdsaPublicKey, OPENSSL_ALGO_SHA512);

        return $signature;
    }


    /**
     * Кодирует данные в формате base64url.
     *
     * Эта функция кодирует данные в формате base64url, который является URL-безопасной версией
     * кодировки base64. Она заменяет символы '+', '/' и '=' на '-', '_' и '' соответственно.
     *
     * @param mixed $inputData Данные для кодирования в формате base64url.
     *
     * @return string Возвращает строку в формате base64url, представляющую закодированные данные.
     *
     * @see https://www.php.net/manual/en/function.base64-encode.php
     */
    private static function base64UrlEncode(mixed $inputData): string
    {
        // Кодируем данные в формате base64
        $base64EncodedData = base64_encode($inputData);
        // Заменяем символы '+', '/' и '=' на '-', '_' и '' соответственно
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64EncodedData);
    }

    /**
     * Декодирует данные из формата base64url.
     *
     * Эта функция декодирует данные из формата base64url, который является URL-безопасной версией
     * кодировки base64. Она заменяет символы '-', '_' и '' на '+', '/' и '=' соответственно.
     *
     * @param string $inputData Строка в формате base64url для декодирования.
     *
     * @return false|string Возвращает декодированные данные или false, если произошла ошибка.
     *
     * @see https://www.php.net/manual/en/function.base64-decode.php
     */
    private static function base64UrlDecode(string $inputData): false|string
    {
        // Вычисляем остаток от деления длины строки на 4
        $remainder = strlen($inputData) % self::BASE64_GROUP_SIZE;
        if ($remainder) {
            // Если остаток не равен нулю, добавляем символы '=' в конец строки
            $padlen = self::BASE64_GROUP_SIZE - $remainder;
            $inputData .= str_repeat('=', $padlen);
        }
        // Заменяем символы '-', '_' и '' на '+', '/' и '=' соответственно
        $base64EncodedData = str_replace(['-', '_'], ['+', '/'], $inputData);
        // Декодируем данные из формата base64
        return base64_decode($base64EncodedData);
    }

    /**
     * Декодирует JSON-строку.
     *
     * Эта функция декодирует JSON-строку и возвращает ассоциативный массив. Она также принимает
     * дополнительные флаги для управления поведением декодирования. Если при декодировании
     * произошла ошибка, функция выбрасывает исключение DomainException с сообщением об ошибке.
     *
     * @param string $jsonString JSON-строка для декодирования.
     *
     * @return mixed Возвращает ассоциативный массив, представляющий декодированные данные.
     *
     * @throws DomainException Если при декодировании произошла ошибка.
     *
     * @see https://www.php.net/manual/en/function.json-decode.php
     * @see https://www.php.net/manual/en/function.json-last-error.php
     */
    private static function jsonDecode(string $jsonString): mixed
    {
        // Декодируем JSON-строку с использованием указанных флагов
        $decodedData = json_decode($jsonString, true, self::JSON_MAX_DEPTH, JSON_BIGINT_AS_STRING);

        // Проверяем наличие ошибок при декодировании JSON
        if ($errno = json_last_error()) {
            // Определяем сообщения об ошибках для разных типов ошибок
            $messages = [
                JSON_ERROR_DEPTH => 'Превышена максимальный объём стека',
                JSON_ERROR_STATE_MISMATCH => 'Некорректный JSON',
                JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
                JSON_ERROR_SYNTAX => 'Ошибка синтаксиса, некорректный JSON',
                JSON_ERROR_UTF8 => 'Некорректный UTF-8' //PHP >= 5.3.3
            ];
            // Выбрасываем исключение с соответствующим сообщением об ошибке
            throw new DomainException(
                $messages[$errno] ?? 'Ошибка JSON: ' . $errno
            );
        } elseif ($decodedData === null && $jsonString !== 'null') {
            // Если данные равны null, но строка не равна 'null', выбрасываем исключение
            throw new DomainException('Попытка интерпретировать не-JSON');
        }

        // Возвращаем декодированные данные
        return $decodedData;
    }


    /**
     * Кодирует данные в формате JSON.
     *
     * Эта функция кодирует данные в формате JSON и возвращает полученную строку. Она также принимает
     * дополнительные флаги для управления поведением кодирования. Если при кодировании произошла ошибка,
     * функция выбрасывает исключение DomainException с сообщением об ошибке.
     *
     * @param mixed $inputData Данные для кодирования в формате JSON.
     *
     * @return string Возвращает строку в формате JSON, представляющую закодированные данные.
     *
     * @throws DomainException Если при кодировании произошла ошибка.
     *
     * @see https://www.php.net/manual/en/function.json-encode.php
     * @see https://www.php.net/manual/en/function.json-last-error.php
     */
    private static function jsonEncode(mixed $inputData): string
    {
        // Кодируем данные в формате JSON с использованием указанных флагов
        $jsonEncodedData = json_encode($inputData, JSON_UNESCAPED_SLASHES);

        // Проверяем наличие ошибок при кодировании JSON
        if ($errno = json_last_error()) {
            // Определяем сообщения об ошибках для разных типов ошибок
            $messages = [
                JSON_ERROR_DEPTH => 'Превышена максимальный объём стека',
                JSON_ERROR_STATE_MISMATCH => 'Некорректный JSON',
                JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
                JSON_ERROR_SYNTAX => 'Ошибка синтаксиса, некорректный JSON',
                JSON_ERROR_UTF8 => 'Некорректный UTF-8',
            ];
            // Выбрасываем исключение с соответствующим сообщением об ошибке
            throw new DomainException($messages[$errno] ?? 'Ошибка JSON: ' . $errno);
        } elseif ($jsonEncodedData === false) {
            // Если результат кодирования равен false, выбрасываем исключение
            throw new DomainException('Попытка интерпретировать не-JSON');
        }

        // Возвращаем закодированную строку
        return $jsonEncodedData;
    }


    /**
     * Сравнивает две строки с использованием константного времени.
     *
     * Эта функция сравнивает две строки с использованием константного времени, чтобы предотвратить
     * атаки по времени. Она использует встроенную функцию hash_equals, если она доступна,
     * и реализует свой алгоритм сравнения в противном случае.
     *
     * @param string $firstString Первая строка для сравнения.
     * @param string $secondString Вторая строка для сравнения.
     *
     * @return bool Возвращает true, если строки равны, и false в противном случае.
     *
     * @see https://www.php.net/manual/en/function.hash-equals.php
     */
    private static function hashEquals(string $firstString, string $secondString): bool
    {
        static $native = null;
        if ($native === null) {
            $native = function_exists('hash_equals');
        }
        if ($native) {
            // Используем встроенную функцию hash_equals для сравнения строк
            return hash_equals($firstString, $secondString);
        }

        // Определяем минимальную длину строк
        $len = min(self::safeStrlen($firstString), self::safeStrlen($secondString));

        // Сравниваем строки побайтово
        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            // Используем побитовое XOR для сравнения байтов
            $status |= (ord($firstString[$i]) ^ ord($secondString[$i]));
        }
        // Сравниваем длины строк
        $status |= (self::safeStrlen($firstString) ^ self::safeStrlen($secondString));

        // Возвращаем результат сравнения
        return ($status === self::STRINGS_MATCH);
    }

    /**
     * Возвращает длину строки в безопасном режиме.
     *
     * Эта функция возвращает длину строки, используя функцию mb_strlen, если она доступна,
     * и функцию strlen в противном случае. Она предназначена для использования в ситуациях,
     * когда необходимо получить длину строки в байтах, а не в символах.
     *
     * @param string $inputString Строка, длина которой нужно получить.
     *
     * @return int Возвращает длину строки в байтах.
     *
     * @see https://www.php.net/manual/en/function.mb-strlen.php
     * @see https://www.php.net/manual/en/function.strlen.php
     */
    private static function safeStrlen(string $inputString): int
    {
        static $exists = null;
        if ($exists === null) {
            $exists = extension_loaded('mbstring') && function_exists('mb_strlen');
        }
        if ($exists) {
            // Используем функцию mb_strlen с кодировкой '8bit' для получения длины строки в байтах
            return mb_strlen($inputString, self::MBSTRING_ENCODING);
        } else {
            // Используем функцию strlen для получения длины строки в байтах
            return strlen($inputString);
        }
    }


}