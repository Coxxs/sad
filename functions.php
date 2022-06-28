<?php

function binToUint64LE(string $bin): int {
    return unpack('P', $bin)[1];
}

function binToUint32LE(string $bin): int {
    return unpack('V', $bin)[1];
}

/**
 * @param int $subkey_len
 * @param int $subkey_id
 * @param string $context
 * @param string $key
 * @return string
 * @throws SodiumException
 */
function crypto_kdf_derive_from_key(
    $subkey_len,
    $subkey_id,
    $context,
    $key
) {
    ParagonIE_Sodium_Core_Util::declareScalarType($subkey_len, 'int', 1);
    ParagonIE_Sodium_Core_Util::declareScalarType($subkey_id, 'int', 2);
    ParagonIE_Sodium_Core_Util::declareScalarType($context, 'string', 3);
    ParagonIE_Sodium_Core_Util::declareScalarType($key, 'string', 4);
    $subkey_id = (int) $subkey_id;
    $subkey_len = (int) $subkey_len;
    $context = (string) $context;
    $key = (string) $key;

    if ($subkey_len < ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN) {
        throw new SodiumException('subkey cannot be smaller than SODIUM_CRYPTO_KDF_BYTES_MIN');
    }
    if ($subkey_len > ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MAX) {
        throw new SodiumException('subkey cannot be larger than SODIUM_CRYPTO_KDF_BYTES_MAX');
    }
    if ($subkey_id < 0) {
        // throw new SodiumException('subkey_id cannot be negative');
    }
    if (ParagonIE_Sodium_Core_Util::strlen($context) !== 8) {
        throw new SodiumException('context should be SODIUM_CRYPTO_KDF_CONTEXTBYTES bytes');
    }
    if (ParagonIE_Sodium_Core_Util::strlen($key) !== ParagonIE_Sodium_Compat::CRYPTO_KDF_KEYBYTES) {
        throw new SodiumException('key should be SODIUM_CRYPTO_KDF_KEYBYTES bytes');
    }

    $salt = ParagonIE_Sodium_Core_Util::store64_le($subkey_id);
    $state = ParagonIE_Sodium_Compat::crypto_generichash_init_salt_personal(
        $key,
        $subkey_len,
        $salt,
        $context
    );
    return ParagonIE_Sodium_Compat::crypto_generichash_final($state, $subkey_len);
}