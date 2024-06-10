<?php
/**
 * @package     Localzet Web Token Generator
 * @link        https://github.com/localzet/LWT
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2018-2024 Zorin Projects S.P.
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 *
 *              This program is free software: you can redistribute it and/or modify
 *              it under the terms of the GNU Affero General Public License as published
 *              by the Free Software Foundation, either version 3 of the License, or
 *              (at your option) any later version.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *              GNU Affero General Public License for more details.
 *
 *              You should have received a copy of the GNU Affero General Public License
 *              along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *              For any questions, please contact <creator@localzet.com>
 */

declare(strict_types=1);

namespace localzet;

use DomainException;
use Exception;
use RuntimeException;
use SodiumException;
use Throwable;
use UnexpectedValueException;
use function strlen;

/**
 * Класс LWT (Localzet Web Token)
 *
 * Этот класс предназначен для работы с LWT-токенами. LWT-токены - это специфический тип JWT-токенов,
 * используемых для аутентификации и передачи информации между двумя сторонами.
 *
 * @link https://tools.ietf.org/html/rfc7519 Официальная документация по JWT-токенам
 */
final class LWT
{
    /**
     * Тип токена
     *
     * @var string TYPE
     */
    private const TYPE = 'LWTv3';

    /**
     * Допустимые алгоритмы шифрования для данных токена
     *
     * @var array ALLOWED_JWA
     */
    private const ALLOWED_JWA = [
        'HS256', 'HS384', 'HS512',          // Симметричные алгоритмы
        'RS256', 'RS384', 'RS512',          // Асимметричные алгоритмы (RSA-PKCS#1)
        'ES256', 'ES384', 'ES512',          // Асимметричные алгоритмы, основанные на эллиптической кривой
        'EdDSA',                            // Асимметричный алгоритм, основанный на кривой Эдвардса (Ed25519 или Ed448)
        'RS1', 'HS1', 'HS256/64', 'ES256K', // Экспериментальные алгоритмы
        /*
            RS1 и HS1 используют алгоритм хэширования SHA-1
            HS256/64 после генерации сигнатуры оставляет только первые 8 символов
            ES256K выделен для ECDSA на кривой secp256k1
        */
    ];

    /**
     * Алгоритм шифрования для сигнатуры токена
     *
     * Определяет алгоритм шифрования, который будет использоваться для создания цифровой подписи токена.
     *
     * @var string $ALGORITHM
     */
    protected static string $ALGORITHM = 'ES512';

    /**
     * Ключ подписи в формате PEM
     *
     * Используется для создания/проверки цифровой подписи токена.
     *
     * @var string|null $SIGN_KEY
     */
    protected static ?string $SIGN_KEY = null;

    /**
     * Алгоритм симметричного шифрования данных
     *
     * Используется для шифрования данных перед их помещением в токен.
     * Поддерживаемые алгоритмы можно получить - openssl_get_cipher_methods()
     * @see https://www.php.net/manual/ru/function.openssl-get-cipher-methods.php
     *
     * @var string $DATA_SYMMETRIC_ENCRYPTION
     */

    protected static string $DATA_SYMMETRIC_ENCRYPTION = 'AES-256-CBC';

    /**
     * Ключ в формате PEM (RSA)
     *
     * Используется для шифрования/расшифровки данных из токена.
     *
     * @var string|null $DATA_KEY
     */
    protected static ?string $DATA_KEY = null;

    /**
     * Алгоритм асимметричного шифрования данных
     *
     * Используется для шифрования данных перед их помещением в токен.
     *
     * @var string DATA_ASYMMETRIC_ENCRYPTION
     */
    private const DATA_ASYMMETRIC_ENCRYPTION = 'RSA';

    /**
     * Padding асимметричного шифрования данных
     *
     * Используется при асимметричном шифровании данных.
     * Он устойчив к атакам Блейхенбахера.
     *
     * @see https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
     *
     * @var int DATA_ASYMMETRIC_PADDING
     */
    protected const DATA_ASYMMETRIC_PADDING = OPENSSL_PKCS1_OAEP_PADDING;
    protected const DATA_ASYMMETRIC_PADDINGS = [
        'OPENSSL_PKCS1_OAEP_PADDING',
        'OPENSSL_PKCS1_PADDING',
        'OPENSSL_SSLV23_PADDING',
        'OPENSSL_NO_PADDING'
    ];

    // Определение констант для работы с данными

    private const AES_KEY_LENGTH_OFFSET = 4;
    private const AES_KEY_LENGTH = 32;
    private const TOKEN_SEGMENTS_COUNT = 3;
    private const HASH_RAW_OUTPUT = true;
    private const OPENSSL_VERIFY_SUCCESS = 1;
    private const BASE64_GROUP_SIZE = 4;
    private const JSON_MAX_DEPTH = 512;
    private const STRINGS_MATCH = 0;
    private const MBSTRING_ENCODING = '8bit';

    public static ?string $CLAIM_KID = null;

    /**
     * Возвращает тип шифрования
     *
     * @return string Тип шифрования
     * @throws UnexpectedValueException Если алгоритм не соответствует ни одному из известных алгоритмов шифрования.
     */
    protected static function getEncryption(): string
    {
        $encryption = match (self::getClaim('alg')) {
            'HS1', 'HS256', 'HS256/64', 'HS384', 'HS512' => 'HMAC',
            'RS1', 'RS256', 'RS384', 'RS512' => 'RSA-PKCS#1',
            'ES256', 'ES256K', 'ES384', 'ES512' => 'ECDSA',
            'EdDSA' => 'EdDSA',

            default => throw new UnexpectedValueException('Недопустимый алгоритм шифрования'),
        };

        if (!$encryption) {
            throw new RuntimeException('Ошибка получения алгоритма шифрования');
        }

        return $encryption;
    }

    /**
     * Возвращает алгоритм хеширования
     *
     * @return string Алгоритм хеширования
     * @throws UnexpectedValueException Если алгоритм не соответствует ни одному из известных алгоритмов хеширования.
     */
    protected static function getHashAlgorithm(): string
    {
        $hashAlgorithm = match (self::getClaim('alg')) {
            'HS1', 'RS1' => 'SHA1',
            'HS256', 'RS256', 'ES256',
            'ES256K', 'HS256/64', 'EdDSA' => 'SHA256',
            'HS384', 'RS384', 'ES384' => 'SHA384',
            'HS512', 'RS512', 'ES512' => 'SHA512',

            default => throw new UnexpectedValueException('Недопустимый алгоритм шифрования'),
        };

        if (!$hashAlgorithm) {
            throw new RuntimeException('Ошибка получения алгоритма хеширования');
        }

        return $hashAlgorithm;
    }

    protected static function getClaim($claim): ?string
    {
        return match ($claim) {
            // Утверждения заголовка
            'typ' => self::TYPE,
            'cty' => self::$DATA_KEY ? 'LZX' : 'JWS',
            'alg' => self::$ALGORITHM,
            'kid' => self::$CLAIM_KID,
            'enc' => self::$DATA_KEY ? self::$DATA_SYMMETRIC_ENCRYPTION . '+' . self::DATA_ASYMMETRIC_ENCRYPTION : null,

            // Утверждения полезной нагрузки
            // 'iss' => 'Issuer',
            // 'sub' => 'Subject',
            // 'aud' => 'Audience',
            // 'nbf' => 'Not Before',
            // 'iat' => 'Issued At',
            // 'jti' => 'JWT ID',

            default => throw new UnexpectedValueException('Незарегистрированное утверждение JWT')
        };
    }

    /**
     * Кодирует данные в токен.
     *
     * Эта функция кодирует данные в токен и возвращает полученную строку. Она принимает
     * данные, закрытый ключ, публичный ключ и алгоритм шифрования в качестве аргументов.
     * Если эти аргументы не указаны, используются значения по умолчанию, определенные в классе.
     *
     * @param mixed $lwtTokenData Данные для кодирования в токен.
     * @param string|null $signatureKey Закрытый ключ в формате PEM (ECDSA).
     * @param string|null $tokenEncryption Алгоритм шифрования (например, 'HS256', 'RS256').
     * @param string|null $encryptionKey Публичный ключ в формате PEM (RSA).
     *
     * @return string Возвращает строку, представляющую закодированный токен.
     * @throws Exception
     */
    public static function encode(
        mixed  $lwtTokenData,
        string $signatureKey = null,
        string $tokenEncryption = null,
        string $encryptionKey = null,
    ): string
    {
        self::$ALGORITHM = $tokenEncryption;
        self::$SIGN_KEY = $signatureKey;
        self::$DATA_KEY = $encryptionKey;

        if (!self::$ALGORITHM || !self::$SIGN_KEY) {
            throw new UnexpectedValueException("Алгоритм и ключ шифрования не могут быть пустыми");
        }

        if (!in_array(self::$ALGORITHM, self::ALLOWED_JWA)) {
            throw new UnexpectedValueException("Недопустимый алгоритм шифрования");
        }

        // Генерируем сегмент заголовка токена
        $headerSegment = self::generateHeaderSegment();
        // Генерируем сегмент полезной нагрузки токена
        $payloadSegment = self::generatePayloadSegment($lwtTokenData);
        // Генерируем сигнатуру токена
        $signatureSegment = self::generateSignature($headerSegment, $payloadSegment);

        // Возвращаем закодированный токен
        return "$headerSegment.$payloadSegment.$signatureSegment";
    }

    /**
     * Декодирует токен.
     *
     * Эта функция декодирует токен и возвращает расшифрованные данные. Она принимает
     * закодированный токен, публичный ключ, закрытый ключ и алгоритм шифрования в качестве аргументов.
     * Если эти аргументы не указаны, используются значения по умолчанию, определенные в классе.
     *
     * @param string $encodedToken Закодированный токен.
     * @param string|null $signatureKey Публичный ключ в формате PEM (ECDSA).
     * @param string|null $tokenEncryption Алгоритм шифрования (например, 'HS256', 'RS256').
     * @param string|null $encryptionKey Закрытый ключ в формате PEM (RSA).
     *
     * @return mixed Возвращает расшифрованные данные из токена.
     *
     * @throws UnexpectedValueException Алгоритм и ключ шифрования не могут быть пустыми
     * @throws UnexpectedValueException Недопустимый алгоритм шифрования
     * @throws UnexpectedValueException Неверное кол-во сегментов
     * @throws Exception
     */
    public static function decode(
        string $encodedToken,
        string $signatureKey = null,
        string $tokenEncryption = null,
        string $encryptionKey = null,
    ): mixed
    {
        self::$ALGORITHM = $tokenEncryption;
        self::$SIGN_KEY = $signatureKey;
        self::$DATA_KEY = $encryptionKey;

        if (!self::$ALGORITHM || !self::$SIGN_KEY) {
            throw new UnexpectedValueException("Алгоритм и ключ шифрования не могут быть пустыми");
        }

        if (!in_array(self::$ALGORITHM, self::ALLOWED_JWA)) {
            throw new UnexpectedValueException("Недопустимый алгоритм шифрования");
        }

        // Разбиваем токен на сегменты
        $segments = explode('.', $encodedToken);
        if (count($segments) !== self::TOKEN_SEGMENTS_COUNT) {
            // Если токен имеет неверное количество сегментов, выбрасываем исключение
            throw new UnexpectedValueException('Неверное кол-во сегментов');
        }

        // Извлекаем сегменты заголовка, тела и криптографической подписи
        list($headerSegment, $payloadSegment, $signatureSegment) = $segments;

        // Проверяем сегмент заголовка
        self::verifyHeaderSegment($headerSegment);
        // Проверяем сегмент полезной нагрузки и извлекаем расшифрованные данные
        $payload = self::verifyPayloadSegment($payloadSegment);
        // Проверяем сигнатуру токена
        self::verifySignature($headerSegment, $payloadSegment, $signatureSegment);

        // Возвращаем расшифрованные данные
        return $payload;
    }

    /**
     * Генерирует сегмент заголовка токена.
     *
     * Эта функция генерирует сегмент заголовка токена, используя значения по умолчанию
     * для типа токена и алгоритма шифрования, которые определены в классе.
     *
     * @return string Возвращает сегмент заголовка токена в формате base64url.
     */
    protected static function generateHeaderSegment(): string
    {
        // Генерируем заголовок токена
        $header = array_filter(
            [
                'typ' => self::getClaim('typ'),
                'cty' => self::getClaim('cty'),
                'alg' => self::getClaim('alg'),
                'kid' => self::getClaim('kid'),
                'enc' => self::getClaim('enc'),
            ],
            function ($value) {
                return $value && $value != null;
            }
        );

        // Кодируем заголовок в формате JSON
        $headerJson = self::jsonEncode($header);

        // Кодируем заголовок в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($headerJson);
    }

    /**
     * Проверяет сегмент заголовка токена.
     *
     * Эта функция проверяет сегмент заголовка токена. Она проверяет, что тип токена и алгоритм
     * шифрования соответствуют значениям по умолчанию, определенным в классе. Если проверка не пройдена,
     * функция выбрасывает исключение UnexpectedValueException.
     *
     * @param string $lwtTokenHeaderSegment Сегмент заголовка токена.
     *
     * @throws UnexpectedValueException Если тип токена или алгоритм шифрования не соответствуют значениям по умолчанию.
     */
    protected static function verifyHeaderSegment(string $lwtTokenHeaderSegment): void
    {
        // Декодируем сегмент заголовка из формата base64url
        $headerJson = self::base64UrlDecode($lwtTokenHeaderSegment);

        // Декодируем заголовок из формата JSON
        $header = self::jsonDecode($headerJson);

        // Проверяем, что тип токена и алгоритм шифрования соответствуют значениям по умолчанию
        if (
            !isset($header['typ']) ||
            !isset($header['cty']) ||
            !isset($header['alg']) ||
            $header['typ'] !== self::getClaim('typ') ||
            $header['cty'] !== self::getClaim('cty') ||
            $header['alg'] !== self::getClaim('alg')
        ) {
            // Если проверка не пройдена, выбрасываем исключение
            throw new UnexpectedValueException('Ошибка шифрования заголовка');
        }
    }


    /**
     * Генерирует сегмент полезной нагрузки токена.
     *
     * Эта функция генерирует сегмент полезной нагрузки токена, используя данные и публичный ключ.
     * Она кодирует данные в формате JSON, шифрует их с помощью алгоритмов AES и RSA, и возвращает
     * полученную строку в формате base64url.
     *
     * @param mixed $lwtTokenData Данные для кодирования в токен.
     *
     * @return string Возвращает сегмент полезной нагрузки токена в формате base64url.
     *
     * @see https://tools.ietf.org/html/rfc7519
     * @see https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php
     * @see https://www.php.net/manual/en/function.openssl-public-encrypt.php
     * @see https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     */
    protected static function generatePayloadSegment(mixed $lwtTokenData): string
    {
        // Кодируем данные в формате JSON
        $payloadData = self::jsonEncode($lwtTokenData);

        // Проверяем, указан ли публичный ключ или установлен ли он по умолчанию
        if (self::$DATA_KEY) {
            // Генерируем временный ключ AES
            $aesKey = openssl_random_pseudo_bytes(self::AES_KEY_LENGTH);

            if (!$aesKey) {
                throw new RuntimeException('Ошибка генерации ключа AES');
            }

            $padding = self::DATA_ASYMMETRIC_PADDING;
            foreach (self::DATA_ASYMMETRIC_PADDINGS as $paddingMode) {
                if (defined($paddingMode)) {
                    $padding = constant($paddingMode);
                    break;
                }
            }

            // Зашифровываем ключ AES с помощью шифрования RSA
            if (@openssl_pkey_get_public(self::$DATA_KEY)) {
                $encrypt = openssl_public_encrypt($aesKey, $encryptedAesKey, self::$DATA_KEY, $padding);
            } elseif (@openssl_pkey_get_private(self::$DATA_KEY)) {
                $encrypt = openssl_private_encrypt($aesKey, $encryptedAesKey, self::$DATA_KEY, $padding);
            } else {
                throw new RuntimeException('Ошибка ключа RSA');
            }

            if (!$encrypt) {
                throw new RuntimeException('Ошибка шифрования ключа AES: ' . openssl_error_string());
            }

            // Генерируем вектор инициализации для алгоритма AES
            $initializationVectorLength = openssl_cipher_iv_length(self::$DATA_SYMMETRIC_ENCRYPTION);
            $initializationVector = openssl_random_pseudo_bytes($initializationVectorLength);

            if (!$initializationVector) {
                throw new RuntimeException('Ошибка генерации вектора инициализации');
            }

            // Шифруем данные с помощью алгоритма AES
            $encryptedPayloadData = openssl_encrypt($payloadData, self::$DATA_SYMMETRIC_ENCRYPTION, $aesKey, 0, $initializationVector);

            if (!$encryptedPayloadData) {
                throw new RuntimeException('Ошибка шифрования данных');
            }

            // Формируем полезную нагрузку токена, добавляя информацию о длине ключа и сам ключ AES,
            // а также вектор инициализации и зашифрованные данные
            $payloadData = pack('N', self::AES_KEY_LENGTH_OFFSET + strlen($encryptedAesKey)) . $encryptedAesKey . $initializationVector . $encryptedPayloadData;
        }

        // Кодируем полезную нагрузку токена в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($payloadData);
    }

    /**
     * Проверяет сегмент полезной нагрузки токена.
     *
     * Эта функция проверяет сегмент полезной нагрузки токена. Она расшифровывает данные,
     * используя закрытый ключ и алгоритмы AES и RSA, и возвращает расшифрованные данные. Если при
     * расшифровке произошла ошибка, функция выбрасывает исключение RuntimeException.
     *
     * @param string $lwtTokenPayloadSegment Сегмент полезной нагрузки токена.
     *
     * @return mixed Возвращает расшифрованные данные из токена.
     *
     * @throws RuntimeException Неверная длина ключа AES.
     * @throws RuntimeException Ошибка расшифровки ключа AES.
     * @throws RuntimeException Ошибка расшифровки данных.
     *
     * @see https://www.php.net/manual/en/function.unpack.php
     * @see https://www.php.net/manual/en/function.substr.php
     * @see https://www.php.net/manual/en/function.openssl-private-decrypt.php
     * @see https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     */
    protected static function verifyPayloadSegment(string $lwtTokenPayloadSegment): mixed
    {
        // Декодируем тело из base64url
        $payloadData = self::base64UrlDecode($lwtTokenPayloadSegment);

        if (self::$DATA_KEY) {

            // Извлекаем длину зашифрованного ключа AES из данных
            $encryptedAesKeyLength = (int)@unpack('Ntotal_length', $payloadData)['total_length'] - self::AES_KEY_LENGTH_OFFSET;

            if ($encryptedAesKeyLength <= 0) {
                throw new RuntimeException('Неверная длина ключа AES');
            }

            // Извлекаем зашифрованный ключ AES из данных
            $encryptedAesKey = substr($payloadData, self::AES_KEY_LENGTH_OFFSET, $encryptedAesKeyLength);

            // Удаляем информацию о длине ключа и сам ключ из данных
            $encryptedPayload = substr($payloadData, self::AES_KEY_LENGTH_OFFSET + $encryptedAesKeyLength);

            $padding = self::DATA_ASYMMETRIC_PADDING;
            foreach (self::DATA_ASYMMETRIC_PADDINGS as $paddingMode) {
                if (defined($paddingMode)) {
                    $padding = constant($paddingMode);
                    break;
                }
            }

            // Расшифровываем ключ AES с помощью шифрования RSA
            if (@openssl_pkey_get_public(self::$DATA_KEY)) {
                $decrypt = openssl_public_decrypt($encryptedAesKey, $aesKey, self::$DATA_KEY, $padding);
            } elseif (@openssl_pkey_get_private(self::$DATA_KEY)) {
                $decrypt = openssl_private_decrypt($encryptedAesKey, $aesKey, self::$DATA_KEY, $padding);
            } else {
                throw new RuntimeException('Ошибка ключа RSA');
            }

            if (!$decrypt) {
                throw new RuntimeException('Ошибка расшифровки ключа AES: ' . openssl_error_string());
            }

            // Извлекаем вектор инициализации из зашифрованных данных
            $initializationVectorLength = openssl_cipher_iv_length(self::$DATA_SYMMETRIC_ENCRYPTION);
            $initializationVector = substr($encryptedPayload, 0, $initializationVectorLength);
            $encryptedPayloadData = substr($encryptedPayload, $initializationVectorLength);

            // Расшифровываем данные с помощью алгоритма AES
            $payloadData = openssl_decrypt($encryptedPayloadData, self::$DATA_SYMMETRIC_ENCRYPTION, $aesKey, 0, $initializationVector);

            if (!$payloadData) {
                throw new RuntimeException('Ошибка расшифровки данных');
            }
        }

        // Декодируем JSON-представление данных
        return self::jsonDecode($payloadData);
    }

    /**
     * Генерирует сигнатуру для токена.
     *
     * Эта функция генерирует сигнатуру для токена.
     *
     * @param string $headerSegment Сегмент заголовка токена.
     * @param string $payloadSegment Сегмент полезной нагрузки токена.
     *
     * @return string Возвращает сигнатуру в формате base64url.
     *
     * @throws SodiumException Ошибка создания подписи.
     * @throws RuntimeException Ошибка создания подписи.
     * @throws UnexpectedValueException Недопустимый алгоритм шифрования.
     * @throws Exception Требуется php-sodium.
     *
     * @see https://www.php.net/manual/en/function.hash-hmac.php
     * @see https://www.php.net/manual/en/function.openssl-sign.php
     */
    protected static function generateSignature(string $headerSegment, string $payloadSegment): string
    {
        $data = "$headerSegment.$payloadSegment";
        $signature = '';

        switch (self::getEncryption()) {
            case 'HMAC':    // 'HS1', 'HS256', 'HS256/64', 'HS384', 'HS512'
                $signature = hash_hmac(self::getHashAlgorithm(), $data, self::generateHmacKeyFromSignKey(), self::HASH_RAW_OUTPUT);
                break;

            case 'RSA-PKCS#1':  // 'RS1', 'RS256', 'RS384', 'RS512'
            case 'ECDSA':   // 'ES256', 'ES256K', 'ES384', 'ES512'
                $success = openssl_sign($data, $signature, self::$SIGN_KEY, self::getHashAlgorithm());
                if (!$success) {
                    throw new RuntimeException('Ошибка создания подписи');
                }
                break;

            case 'EdDSA':  // EdDSA (Ed25519)
                if (!extension_loaded('sodium')) {
                    throw new Exception('Требуется php-sodium');
                }

                $signature = sodium_crypto_sign_detached($data, self::$SIGN_KEY);
                break;

            default:
                throw new UnexpectedValueException('Недопустимый алгоритм шифрования');
        }

        if (self::getClaim('alg') == 'HS256/64') {
            $signature = mb_substr($signature, 0, 8, '8bit');
        }

        // Кодируем подпись в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($signature);
    }

    /**
     * Проверяет сигнатуру токена.
     *
     * Эта функция проверяет сигнатуру токена.
     *
     * @param string $headerSegment Сегмент заголовка токена.
     * @param string $payloadSegment Сегмент полезной нагрузки токена.
     * @param string $signatureSegment Сегмент сигнатуры токена.
     *
     * @throws SodiumException Ошибка верификации сигнатуры.
     * @throws UnexpectedValueException Ошибка верификации сигнатуры.
     * @throws UnexpectedValueException Недопустимый алгоритм шифрования.
     * @throws Exception Требуется php-sodium.
     *
     * @see https://www.php.net/manual/en/function.openssl-verify.php
     * @see https://www.php.net/manual/en/function.hash-hmac.php
     */
    protected static function verifySignature(string $headerSegment, string $payloadSegment, string $signatureSegment): void
    {
        // Проверяем сигнатуру
        $signature = self::base64UrlDecode($signatureSegment);

        $data = "$headerSegment.$payloadSegment";

        switch (self::getEncryption()) {
            case 'HMAC':    // 'HS1', 'HS256', 'HS256/64', 'HS384', 'HS512'
                $hash = hash_hmac(self::getHashAlgorithm(), $data, self::generateHmacKeyFromSignKey(), self::HASH_RAW_OUTPUT);
                if (!self::hashEquals($hash, $signature)) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            case 'RSA-PKCS#1':  // 'RS1', 'RS256', 'RS384', 'RS512'
            case 'ECDSA':   // 'ES256', 'ES256K', 'ES384', 'ES512'
                $verify = openssl_verify($data, $signature, self::$SIGN_KEY, self::getHashAlgorithm());
                if ($verify !== self::OPENSSL_VERIFY_SUCCESS) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            case 'EdDSA':  // EdDSA (Ed25519)
                if (!extension_loaded('sodium')) {
                    throw new Exception('Требуется php-sodium');
                }

                $verify = sodium_crypto_sign_verify_detached($signature, $data, self::$SIGN_KEY);
                if (!$verify) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            default:
                throw new UnexpectedValueException('Недопустимый алгоритм шифрования');
        }
    }

    /**
     * Генерирует HMAC-ключ из ключа подписи.
     *
     * Эта функция использует ключ подписи для генерации HMAC-ключа. Она также использует
     * значения по умолчанию для типа токена, алгоритма шифрования, симметричного и асимметричного
     * методов шифрования, которые определены в классе.
     *
     * @return string Возвращает HMAC-ключ.
     *
     * @throws RuntimeException Ошибка получения закрытого ключа.
     * @throws RuntimeException Ошибка создания подписи.
     *
     * @see https://www.php.net/manual/en/function.openssl-pkey-get-private.php
     * @see https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     * @see https://www.php.net/manual/en/function.openssl-sign.php
     */
    protected static function generateHmacKeyFromSignKey(): string
    {
        // Генерируем предварительный ключ
        $data = self::getClaim('typ') .
            '*' . self::getClaim('cty') .
            '*' . self::getClaim('alg') .
            '*' . self::$DATA_SYMMETRIC_ENCRYPTION .
            '*' . self::DATA_ASYMMETRIC_ENCRYPTION;

        $key = self::$SIGN_KEY;

        $public = @openssl_pkey_get_public($key);
        $private = @openssl_pkey_get_private($key);

        if (!$public && !$private) {
            return $key;
        }

        if ($private) {
            // Получаем информацию о закрытом ключе
            $keyDetails = openssl_pkey_get_details($private);
            // Извлекаем публичный ключ из информации о закрытом ключе
            $key = $keyDetails['key'];
        }

        try {
            // Генерируем криптографическую подпись с использованием ключа и алгоритма SHA-512
            $result = openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA512);
        } catch (Throwable $e) {
            throw new RuntimeException('Ошибка создания подписи: ' . $e->getMessage());
        }

        if (!$result) {
            throw new RuntimeException('Ошибка создания подписи');
        }

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
     *
     * @throws RuntimeException Ошибка кодирования base64
     *
     * @see https://www.php.net/manual/en/function.base64-encode.php
     */
    public static function base64UrlEncode(mixed $inputData): string
    {
        // Кодируем данные в формате base64
        $base64EncodedData = base64_encode($inputData);

        if (!$base64EncodedData) {
            throw new RuntimeException('Ошибка кодирования base64');
        }

        // Заменяем символы '+', '/' и '=' на '-', '_' и '' соответственно
        $base64UrlEncodedData = str_replace(['+', '/', '='], ['-', '_', ''], $base64EncodedData);

        if (!$base64UrlEncodedData) {
            throw new RuntimeException('Ошибка кодирования base64Url');
        }

        return $base64UrlEncodedData;
    }

    /**
     * Декодирует данные из формата base64url.
     *
     * Эта функция декодирует данные из формата base64url, который является URL-безопасной версией
     * кодировки base64. Она заменяет символы '-', '_' и '' на '+', '/' и '=' соответственно.
     *
     * @param string $inputData Строка в формате base64url для декодирования.
     *
     * @return string Возвращает декодированные данные или false, если произошла ошибка.
     *
     * @throws RuntimeException Ошибка декодирования base64
     *
     * @see https://www.php.net/manual/en/function.base64-decode.php
     */
    public static function base64UrlDecode(string $inputData): string
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
        $decodedData = base64_decode($base64EncodedData);

        if (!$decodedData) {
            throw new RuntimeException('Ошибка декодирования base64');
        }

        return $decodedData;
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
     * @throws DomainException Ошибка JSON
     * @throws DomainException Попытка интерпретировать не-JSON
     * @throws RuntimeException Ошибка декодирования JSON
     *
     * @see https://www.php.net/manual/en/function.json-decode.php
     * @see https://www.php.net/manual/en/function.json-last-error.php
     */
    protected static function jsonDecode(string $jsonString): mixed
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
            // } elseif ($decodedData === null && $jsonString !== 'null') {
            //     // Если данные равны null, но строка не равна 'null', выбрасываем исключение
            //     throw new DomainException('Попытка интерпретировать не-JSON');
        }

        // if (!$decodedData) {
        //     // Если при расшифровке произошла другая ошибка
        //     throw new RuntimeException('Ошибка декодирования JSON');
        // }

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
     * @throws RuntimeException Ошибка кодирования JSON.
     * @throws DomainException Ошибка JSON.
     *
     * @see https://www.php.net/manual/en/function.json-encode.php
     * @see https://www.php.net/manual/en/function.json-last-error.php
     */
    protected static function jsonEncode(mixed $inputData): string
    {
        // Кодируем данные в формате JSON с использованием указанных флагов
        $encodedData = json_encode($inputData, JSON_UNESCAPED_SLASHES);

        if (!$encodedData) {
            throw new RuntimeException('Ошибка кодирования JSON');
        }

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
        }

        // Возвращаем закодированную строку
        return $encodedData;
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
    protected static function hashEquals(string $firstString, string $secondString): bool
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
     * @throws RuntimeException Ошибка получения длины строки
     *
     * @see https://www.php.net/manual/en/function.mb-strlen.php
     * @see https://www.php.net/manual/en/function.strlen.php
     */
    protected static function safeStrlen(string $inputString): int
    {
        static $exists = null;
        if ($exists === null) {
            $exists = extension_loaded('mbstring') && function_exists('mb_strlen');
        }
        if ($exists) {
            // Используем функцию mb_strlen с кодировкой '8bit' для получения длины строки в байтах
            $length = mb_strlen($inputString, self::MBSTRING_ENCODING);
        } else {
            // Используем функцию strlen для получения длины строки в байтах
            $length = strlen($inputString);
        }

        if (!$length) {
            throw new RuntimeException('Ошибка получения длины строки');
        }

        return $length;
    }
}
