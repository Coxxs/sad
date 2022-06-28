<?php
require_once 'vendor/autoload.php';
require_once 'functions.php';
use \MessagePack\MessagePack;

class InvalidKeyException extends Exception {}

function deriveKey(string $header, string $masterkey) {
    $kid = binToUint64LE(substr($header, 16, 8));
    $context = substr($header, 24, 8);
    $context[7] = "\0";

    $key = crypto_kdf_derive_from_key(32, $kid, $context, $masterkey);
    return $key;
}

function parseArchive(string $archive, array $masterkeys) {
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
    $success = false;
    $validkeys = [];
    foreach ($masterkeys as $masterkey) {
        $pptr = $ptr;
        $key = deriveKey($meta[0], $masterkey);

        $files = $meta[1];
        $data = '';
        foreach ($files as $file) {
            $len = $file[0];
            $hash = $file[1];
            assert($hash != null);
    
            $filedata = substr($archive, $pptr, $len);
            $pptr += $len;
            try {
                $data .= decryptFile_tar($filedata, $key, $hash);
                if (!in_array($masterkey, $validkeys)) {
                    echo 'Found valid key: '.bin2hex($masterkey).nl2br("\n");
                    $validkeys []= $masterkey;
                }
            } catch (InvalidKeyException $err) {
                goto END;
            }
            
        }
    
        $data .= str_repeat("\0", 0x400);
        $success = true;
        break;
        END:
    }
    if (!$success) {
        throw new InvalidKeyException("Unable to find a valid key!");
    }
    return $data;
}
    
function padTar(string &$data) {
    $pad = strlen($data) % 0x200;
    if ($pad === 0) {
        return '';
    }
    return str_repeat("\0", 0x200 - $pad);
}

function decryptFile_tar(string $file, string $key, string $hash = null) {
    if ($hash != null) {
        assert(sodium_crypto_generichash($file) === $hash);
    }
    $ptr = 0;

    $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($file, $ptr, 24), $key);
    $ptr += 24;

    $header = sodium_crypto_secretstream_xchacha20poly1305_pull($state, substr($file, $ptr, 403));
    if (!$header) {
        throw new InvalidKeyException();
    }
    assert($header[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
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

$masterkeys = [
    hex2bin('50EB........................................................1ADE'),
    hex2bin('64FA........................................................3FE0'),
    // ...
];
$filename = 'file.spk'; // file.sa
$file = file_get_contents($filename);
$data = parseArchive($file, $masterkeys);

if ($data) {
    echo 'Success';
    file_put_contents($filename.'.tar', $data);
} else {
    echo 'Failure';
}