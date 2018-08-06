<?php
namespace Hyperwallet\Util;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\UriTemplate;
use Hyperwallet\Exception\HyperwalletApiException;
use Hyperwallet\Exception\HyperwalletException;
use Hyperwallet\Model\BaseModel;
use Hyperwallet\Response\ErrorResponse;

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Hash;
use JOSE_URLSafeBase64;
use JOSE_JWS;
use JOSE_JWE;
use JOSE_JWK;
use JOSE_JWT;

class HyperwalletEncryption {

    private $clientPrivateKeySetLocation;
    private $hyperwalletKeySetLocation;
    private $encryptionAlgorithm;
    private $signAlgorithm;
    private $encryptionMethod;
    private $jwsExpirationMinutes;
    private $jwsKid;
    private $jweKid;

    public function __construct($clientPrivateKeySetLocation, $hyperwalletKeySetLocation,
                $encryptionAlgorithm = 'RSA-OAEP-256', $signAlgorithm = 'RS256', $encryptionMethod = 'A256CBC-HS512',
                $jwsExpirationMinutes = 5) {
        $this->clientPrivateKeySetLocation = $clientPrivateKeySetLocation;
        $this->hyperwalletKeySetLocation = $hyperwalletKeySetLocation;
        $this->encryptionAlgorithm = $encryptionAlgorithm;
        $this->signAlgorithm = $signAlgorithm;
        $this->encryptionMethod = $encryptionMethod;
        $this->jwsExpirationMinutes = $jwsExpirationMinutes;
        file_put_contents(__DIR__ . "/../../../vendor/gree/jose/src/JOSE/JWE.php", file_get_contents(__DIR__ . "/../../JWE.php"));
    }

    public function encrypt($body) {
        $privateJwsKey = $this->getPrivateJwsKey();
        $jws = new JOSE_JWS(new JOSE_JWT($body));
        $jws->header['exp'] = $this->getSignatureExpirationTime();
        $jws->header['kid'] = $this->jwsKid;
        $jws->sign($privateJwsKey, $this->signAlgorithm);

        $publicJweKey = $this->getPublicJweKey();
        $jwe = new JOSE_JWE($jws);
        $jwe->header['kid'] = $this->jweKid;
        $jwe->encrypt($publicJweKey, $this->encryptionAlgorithm, $this->encryptionMethod);
        return $jwe->toString();
    }

    public function decrypt($body) {
        $privateJweKey = $this->getPrivateJweKey();
        $jwe = JOSE_JWT::decode($body);
        $decryptedBody = $jwe->decrypt($privateJweKey);

        $publicJwsKey = $this->getPublicJwsKey();
        $jwsToVerify = JOSE_JWT::decode($decryptedBody->plain_text);
        $this->checkJwsExpiration($jwsToVerify->header);
        $jwsVerificationResult = $jwsToVerify->verify($publicJwsKey, $this->signAlgorithm);
        return $jwsVerificationResult->claims;
    }

    private function getPrivateJwsKey() {
        $privateKeyData = $this->getJwk($this->clientPrivateKeySetLocation, $this->signAlgorithm);
        $this->jwsKid = $privateKeyData['kid'];
        return $this->getPrivateKey($privateKeyData);
    }

    private function getPublicJweKey() {
        $publicKeyData = $this->getJwk($this->hyperwalletKeySetLocation, $this->encryptionAlgorithm);
        $this->jweKid = $publicKeyData['kid'];
        return $this->getPublicKey($this->convertPrivateKeyToPublic($publicKeyData));
    }

    private function getPrivateJweKey() {
        $privateKeyData = $this->getJwk($this->clientPrivateKeySetLocation, $this->encryptionAlgorithm);
        return $this->getPrivateKey($privateKeyData);
    }

    private function getPublicJwsKey() {
        $publicKeyData = $this->getJwk($this->hyperwalletKeySetLocation, $this->signAlgorithm);
        return $this->getPublicKey($this->convertPrivateKeyToPublic($publicKeyData));
    }

    private function getPrivateKey($privateKeyData) {
        $n = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['n'])), 16);
        $e = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['e'])), 16);
        $d = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['d'])), 16);
        $p = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['p'])), 16);
        $q = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['q'])), 16);
        $qi = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['qi'])), 16);
        $dp = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['dp'])), 16);
        $dq = new BigInteger('0x' . bin2hex(JOSE_URLSafeBase64::decode($privateKeyData['dq'])), 16);
        $primes = array($p, $q);
        $exponents = array($dp, $dq);
        $coefficients = array($qi, $qi);
        array_unshift($primes, "phoney");
        unset($primes[0]);
        array_unshift($exponents, "phoney");
        unset($exponents[0]);
        array_unshift($coefficients, "phoney");
        unset($coefficients[0]);

        $pemData = (new RSA())->_convertPrivateKey($n, $e, $d, $primes, $exponents, $coefficients);
        $privateKey = new RSA();
        $privateKey->loadKey($pemData);
        if ($privateKeyData['alg'] == 'RSA-OAEP-256') {
            $privateKey->setHash('sha256');
            $privateKey->setMGFHash('sha256');
        }
        return $privateKey;
    }

    private function getPublicKey($publicKeyData) {
        $publicKeyRaw = new JOSE_JWK($publicKeyData);
        $publicKey = $publicKeyRaw->toKey();
        if ($publicKeyData['alg'] == 'RSA-OAEP-256') {
            $publicKey->setHash('sha256');
            $publicKey->setMGFHash('sha256');
        }
        return $publicKey;
    }

    private function getJwk($keySetLocation, $alg) {
        if (filter_var($keySetLocation, FILTER_VALIDATE_URL) === FALSE) {
            if (!file_exists($keySetLocation)) {
                throw new HyperwalletException("Wrong JWK key set location path = " . $keySetLocation);
            }
        }
        return $this->findJwkByAlgorithm(json_decode(file_get_contents($keySetLocation), true), $alg);
    }

    private function findJwkByAlgorithm($jwkSetArray, $alg) {
        foreach($jwkSetArray['keys'] as $jwk) {
            if ($alg == $jwk['alg']) {
                return $jwk;
            }
        }
        throw new HyperwalletException("JWK set doesn't contain key with algorithm = " . $alg);
    }

    private function convertPrivateKeyToPublic($jwk) {
        if (isset($jwk['d'])) {
            unset($jwk['d']);
        }
        if (isset($jwk['p'])) {
            unset($jwk['p']);
        }
        if (isset($jwk['q'])) {
            unset($jwk['q']);
        }
        if (isset($jwk['qi'])) {
            unset($jwk['qi']);
        }
        if (isset($jwk['dp'])) {
            unset($jwk['dp']);
        }
        if (isset($jwk['dq'])) {
            unset($jwk['dq']);
        }
        return $jwk;
    }

    private function getSignatureExpirationTime() {
        date_default_timezone_set("UTC");
        $secondsInMinute = 60;
        return time() + $this->jwsExpirationMinutes * $secondsInMinute;
    }

    public function checkJwsExpiration($header) {
        if(!isset($header['exp'])) {
            throw new HyperwalletException('While trying to verify JWS signature no [exp] header is found');
        }
        $exp = $header['exp'];
        if(!is_numeric($exp)) {
            throw new HyperwalletException('Wrong value in [exp] header of JWS signature, must be integer');
        }
        if((int)time() > (int)$exp) {
            throw new HyperwalletException('JWS signature has expired, checked by [exp] JWS header');
        }
    }
}
