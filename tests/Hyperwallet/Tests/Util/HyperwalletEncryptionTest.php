<?php
namespace Hyperwallet\Tests;

use Hyperwallet\Util\HyperwalletEncryption;

class HyperwalletEncryptionTest extends \PHPUnit_Framework_TestCase {

    public function testShouldSuccessfullyEncryptAndDecryptTextMessage() {
        $clientPath = __DIR__ . "/../../../resources/private-jwkset1";
        $hyperwalletPath = __DIR__ . "/../../../resources/public-jwkset1";
        $originalMessage = "Test message";
        $encryption = new HyperwalletEncryption($clientPath, $hyperwalletPath);
        $encryptedMessage = $encryption->encrypt($originalMessage);
        $decryptedMessage = $encryption->decrypt($encryptedMessage);
        $this->assertEquals($originalMessage, $decryptedMessage['scalar']);
    }

    public function testShouldFailDecryptionWhenWrongPrivateKeyIsUsed() {
        $clientPath1 = __DIR__ . "/../../../resources/private-jwkset1";
        $hyperwalletPath1 = __DIR__ . "/../../../resources/public-jwkset1";
        $clientPath2 = __DIR__ . "/../../../resources/private-jwkset2";
        $hyperwalletPath2 = __DIR__ . "/../../../resources/public-jwkset2";
        $originalMessage = "Test message";
        $encryption1 = new HyperwalletEncryption($clientPath1, $hyperwalletPath1);
        $encryption2 = new HyperwalletEncryption($clientPath2, $hyperwalletPath2);
        $encryptedMessage = $encryption1->encrypt($originalMessage);

        try {
            $encryption2->decrypt($encryptedMessage);
            $this->fail('Exception expected');
        } catch (\Exception $e) {
            $this->assertEquals('Decryption error', $e->getMessage());
        }
    }

    public function testShouldFailSignatureVerificationWhenWrongPublicKeyIsUsed() {
        $clientPath1 = __DIR__ . "/../../../resources/private-jwkset1";
        $hyperwalletPath1 = __DIR__ . "/../../../resources/public-jwkset1";
        $hyperwalletPath2 = __DIR__ . "/../../../resources/public-jwkset2";
        $originalMessage = "Test message";
        $encryption1 = new HyperwalletEncryption($clientPath1, $hyperwalletPath1);
        $encryption2 = new HyperwalletEncryption($clientPath1, $hyperwalletPath2);
        $encryptedMessage = $encryption1->encrypt($originalMessage);

        try {
            $encryption2->decrypt($encryptedMessage);
            $this->fail('Exception expected');
        } catch (\Exception $e) {
            $this->assertEquals('Signature verification failed', $e->getMessage());
        }
    }

    public function testShouldThrowExceptionWhenWrongJwkKeySetLocationIsGiven() {
        $clientPath = "wrong_keyset_path";
        $hyperwalletPath = __DIR__ . "/../../../resources/public-jwkset1";
        $originalMessage = "Test message";
        $encryption = new HyperwalletEncryption($clientPath, $hyperwalletPath);

        try {
            $encryption->encrypt($originalMessage);
            $this->fail('Exception expected');
        } catch (\Exception $e) {
            $this->assertEquals('Wrong JWK key set location path = wrong_keyset_path', $e->getMessage());
        }
    }

    public function testShouldThrowExceptionWhenNotSupportedEncryptionAlgorithmIsGiven() {
        $clientPath = __DIR__ . "/../../../resources/private-jwkset1";
        $hyperwalletPath = __DIR__ . "/../../../resources/public-jwkset1";
        $originalMessage = "Test message";
        $encryption = new HyperwalletEncryption($clientPath, $hyperwalletPath, 'unsupported_encryption_algorithm');

        try {
            $encryption->encrypt($originalMessage);
            $this->fail('Exception expected');
        } catch (\Exception $e) {
            $this->assertEquals('JWK set doesn\'t contain key with algorithm = unsupported_encryption_algorithm', $e->getMessage());
        }
    }
}
