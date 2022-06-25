<?php
require_once 'vendor/autoload.php';
use \MessagePack\MessagePack;

function binToUint64LE($bin) {
    return unpack('P', $bin)[1];
}

function binToUint32LE($bin) {
    return unpack('V', $bin)[1];
}

function deriveKey($header, $masterkey) {
    $kid = binToUint64LE(substr($header, 16, 8));
    $context = substr($header, 24, 8);
    $context[7] = "\0";

    // TODO: PHP not allow subkey_id > PHP_INT_MAX (2^63 - 1), this is a PHP bug.
    $key = sodium_crypto_kdf_derive_from_key(32, $kid, $context, $masterkey);
    return $key;
}

function parseArchive($archive, $masterkey) {
    $magic = substr($archive, 1, 3);
    assert($magic === hex2bin('ADBEEF'));
    
    $msgpacklen = binToUint32LE(substr($archive, 4, 4));
    assert($msgpacklen <= strlen($archive) - 8);

    $ptr = 8;
    $msgpack = substr($archive, $ptr, $msgpacklen);
    $ptr += $msgpacklen;

    $signature = substr($archive, $ptr, 0x40);
    $ptr += 0x40;

    // TODO: check signature of msgpack
    $meta = MessagePack::unpack($msgpack);
    $key = deriveKey($meta[0], $masterkey);

    $files = $meta[1];
    $data = '';
    foreach ($files as $file) {
        $len = $file[0];
        $hash = $file[1];
        assert($hash != null);

        $filedata = substr($archive, $ptr, $len);
        $ptr += $len;

        $data .= decryptFile_tar($filedata, $key, $hash);
    }

    $data .= str_repeat("\0", 0x400);
    return $data;
}
    
function padTar(&$data) {
    $pad = strlen($data) % 0x200;
    if ($pad === 0) {
        return '';
    }
    return str_repeat("\0", 0x200 - $pad);
}

function decryptFile_tar($file, $key, $hash = null) {
    if ($hash != null) {
        assert(sodium_crypto_generichash($file) === $hash);
    }
    $ptr = 0;

    $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($file, $ptr, 24), $key);
    $ptr += 24;

    $header = sodium_crypto_secretstream_xchacha20poly1305_pull($state, substr($file, $ptr, 403));
    assert($header && $header[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
    // var_dump($header);
    $ptr += 403;

    $ptr = 0x200;
    $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($file, $ptr, 24), $key);
    $ptr += 24;

    $data = '';
    $filelen = strlen($file);
    while($filelen - $ptr > 0) {
        $len = $filelen - $ptr;
        if ($len > 0x400011) {
            $len = 0x400000;
            $len += 0x11;
        }
        $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, substr($file, $ptr, $len));
        assert($result);
        $ptr += $len;
        
        if ($result[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE) {
            assert($ptr < $filelen);
        } elseif ($result[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
            assert($ptr === $filelen);
        } else {
            throw new Exception("Unknown tag " + $result[1]);
        }

        $data .= $result[0];
    }

    return $header[0].padTar($header[0]).$data.padTar($data);
}

$masterkey = hex2bin("9AD8........................................................6DD4");
$filename = 'OfflinePack'
$file = file_get_contents($filename.'.sa');
$data = parseArchive($file, $masterkey);

file_put_contents($filename.".tar", $data);
