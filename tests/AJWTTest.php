<?php
namespace Asticode\AJWT\Tests;

use Asticode\AJWT\AJWT;
use Asticode\Toolbox\ExtendedUnitTesting;
use DateTime;
use PHPUnit_Framework_TestCase;

class AJWTTest extends PHPUnit_Framework_TestCase
{

    public function testManipulatePayload()
    {
        // Initialize
        $aInput = [
            'key1' => '"value1"',
            'key2' => 200,
            'key3' => 'spéçial'
        ];

        // Build payload
        $sPayload = ExtendedUnitTesting::callMethod(
            '\Asticode\AJWT\AJWT',
            'buildPayload',
            [$aInput]
        );
        $this->assertEquals('{"key1":"\"value1\"","key2":200,"key3":"spéçial"}', $sPayload);

        // Unbuild payload
        $aPayload = ExtendedUnitTesting::callMethod(
            '\Asticode\AJWT\AJWT',
            'unbuildPayload',
            [$sPayload]
        );
        $this->assertEquals($aInput, $aPayload);
    }

    public function testSignPayload()
    {
        // Initialize
        $sPayload = 'payload';
        $sKey = 'key';

        // Sign payload
        $sSignature = ExtendedUnitTesting::callMethod(
            '\Asticode\AJWT\AJWT',
            'signPayload',
            [$sPayload, $sKey]
        );
        $this->assertEquals('185beceee65a5ed7e43f7cc98530bfab1b0d00679488a47225255d04594fd7f17ed6908e7a08df57ac14c9e56c2fdef83ee9adaf9df2ff9f61465898c5d78c00', bin2hex($sSignature));
    }

    public function testDecodeInvalidMembersCount()
    {
        // Set exception
        $this->setExpectedException('\Asticode\AJWT\Exception\InvalidInputException');

        // Decode
        AJWT::decode('1234', 'key');
    }

    public function testDecodeInvalidSignature()
    {
        // Initialize
        $aInput = ['key' => 'value'];
        $sKey1 = 'key1';
        $sKey2 = 'key2';

        // Encode
        $sAJWT = AJWT::encode($aInput, $sKey1);

        // Decode
        $this->setExpectedException('\Asticode\AJWT\Exception\InvalidSignatureException');
        AJWT::decode($sAJWT, $sKey2);
    }

    public function testDecodeInvalidRequiredKeys()
    {
        // Initialize
        $aInput = ['key' => 'value'];
        $sKey = 'key';
        $aRequiredKeys = ['key', 'test'];

        // Encode
        $sAJWT = AJWT::encode($aInput, $sKey);

        // Decode
        $this->setExpectedException('\Asticode\AJWT\Exception\InvalidPayloadException');
        AJWT::decode($sAJWT, $sKey, $aRequiredKeys);
    }

    public function testDecodeTimestampHasExpired()
    {
        // Initialize
        $aInput = ['key' => 'value'];
        $sKey = 'key';
        $iValidityDuration = 100;
        $oTimestamp = DateTime::createFromFormat('U', time() - $iValidityDuration - 5);

        // Encode
        $sAJWT = AJWT::encode($aInput, $sKey, $oTimestamp);

        // Decode
        AJWT::decode($sAJWT, $sKey, [], $iValidityDuration + 5);
        $this->setExpectedException('\Asticode\AJWT\Exception\InvalidPayloadException');
        AJWT::decode($sAJWT, $sKey, [], $iValidityDuration);
    }

    public function testDecodeTimestampInTheFuture()
    {
        // Initialize
        $aInput = ['key' => 'value'];
        $sKey = 'key';
        $oTimestamp = DateTime::createFromFormat('U', time() +2);

        // Encode
        $sAJWT = AJWT::encode($aInput, $sKey, $oTimestamp);

        // Decode
        $this->setExpectedException('\Asticode\AJWT\Exception\InvalidPayloadException');
        AJWT::decode($sAJWT, $sKey);
    }

    public function testEncodeAndDecode()
    {
        // Initialize
        $aInput = [
            'key1' => '"value1"',
            'key2' => 200,
            'key3' => 'spéçial'
        ];
        $sKey = 'key';
        $oTimestamp = DateTime::createFromFormat('Y-m-d H:i:s', '2016-02-18 00:00:00');
        $sNonce = '1234';

        // Encode
        $sAJWT = AJWT::encode($aInput, $sKey, $oTimestamp, $sNonce);
        $this->assertEquals('eyJrZXkxIjoiXCJ2YWx1ZTFcIiIsImtleTIiOjIwMCwia2V5MyI6InNww6nDp2lhbCIsInRpbWVzdGFtcCI6MTQ1NTc1MzYwMCwibm9uY2UiOjEyMzR9.mesbiSzhpd7luMp55e9sEHqp2sZx4OlfVOn+y8C5rwU44X9yVG2r7xRDhhoCaeR+79rLRdsgl+XfUxSqVEFxQg==', $sAJWT);

        // Decode
        $aPayload = AJWT::decode($sAJWT, $sKey);
        $this->assertEquals($aInput, $aPayload);
    }
}
