<?php
declare(strict_types=1);

require __DIR__ . '/../src/LWT.php';

use localzet\LWT;

function assertSameValue($expected, $actual, string $description): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($description . ': values differ');
    }
}

function expectRejected(callable $operation, string $errorContains): void
{
    try {
        $operation();
    } catch (Throwable $error) {
        if (strpos($error->getMessage(), $errorContains) === false) {
            throw new RuntimeException('Unexpected failure: ' . $error->getMessage(), 0, $error);
        }
        return;
    }
    throw new RuntimeException('Expected token to be rejected: ' . $errorContains);
}

$secret = str_repeat('integration-test-only-secret-', 3);
$data = ['sub' => 'alice', 'role' => 'attendee', 'active' => true];
$token = LWT::encode($data, $secret, 'HS256');
assertSameValue($data, LWT::decode($token, $secret, 'HS256'), 'HS256 roundtrip');
expectRejected(static function () use ($token): void {
    LWT::decode($token, 'wrong-signing-secret', 'HS256');
}, 'сигнатуры');

$segments = explode('.', $token);
$segments[1] = LWT::base64UrlEncode('{"sub":"mallory"}');
expectRejected(static function () use ($segments, $secret): void {
    LWT::decode(implode('.', $segments), $secret, 'HS256');
}, 'сигнатуры');

expectRejected(static function (): void {
    LWT::base64UrlDecode('abcd!');
}, 'base64');

$config = [
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
];
$rsa = openssl_pkey_new($config);
if ($rsa === false || !openssl_pkey_export($rsa, $private)) {
    throw new RuntimeException('RSA test key generation failed');
}
$details = openssl_pkey_get_details($rsa);
$public = $details['key'];

$encrypted = LWT::encode($data, $secret, 'HS256', $public);
assertSameValue($data, LWT::decode($encrypted, $secret, 'HS256', $private), 'Encrypted HS256 roundtrip');

$segments = explode('.', $encrypted);
$segments[1] = LWT::base64UrlEncode('invalid encrypted payload');
expectRejected(static function () use ($segments, $secret, $private): void {
    LWT::decode(implode('.', $segments), $secret, 'HS256', $private);
}, 'сигнатуры');

echo "LWT signed and encrypted payload regression checks: OK\n";
