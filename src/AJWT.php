<?php
namespace Asticode\AJWT;

use Asticode\AJWT\Exception\InvalidInputException;
use Asticode\AJWT\Exception\InvalidPayloadException;
use Asticode\AJWT\Exception\InvalidSignatureException;
use Asticode\Toolbox\ExtendedArray;
use Asticode\Toolbox\ExtendedString;
use DateTime;

class AJWT
{
    public static function encode(array $aInput, $sKey, DateTime $oTimestamp = null, $sNonce = '')
    {
        // Add mandatory information
        if (is_null($oTimestamp)) {
            $oTimestamp = new DateTime();
        }
        $aInput['timestamp'] = $oTimestamp->getTimestamp();
        $aInput['nonce'] = empty($sNonce) ? ExtendedString::random(24) : $sNonce;

        // Build payload
        $sPayload = static::buildPayload($aInput);

        // Sign payload
        $sSignature = static::signPayload($sPayload, $sKey);

        // Return
        return sprintf(
            '%1$s.%2$s',
            base64_encode($sPayload),
            base64_encode($sSignature)
        );
    }
    
    private static function buildPayload(array $aInput)
    {
        // Build payload
        $sPayload = json_encode(
            $aInput,
            JSON_UNESCAPED_UNICODE | JSON_NUMERIC_CHECK | JSON_UNESCAPED_SLASHES
        );

        // Payload is invalid
        if (!$sPayload) {
            throw new InvalidInputException('Unencodable input');
        }

        // Return
        return $sPayload;
    }

    private static function unbuildPayload($sInput)
    {
        // Unbuild payload
        $aPayload = json_decode(
            $sInput,
            true
        );

        // Payload is invalid
        if (is_null($aPayload)) {
            throw new InvalidInputException(sprintf(
                'Malformed JSON <%s>',
                $sInput
            ));
        }

        // Return
        return $aPayload;
    }
    
    private static function signPayload($sPayload, $sKey)
    {
        return hash_hmac(
            'sha512',
            $sPayload,
            $sKey,
            true
        );
    }

    public static function decode($sInput, $sKey, array $aRequiredKeys = [], $iValidityDuration = 0)
    {
        // Split input
        $aExplodedInput = explode('.', $sInput);

        // Invalid input
        if (count($aExplodedInput) !== 2) {
            throw new InvalidInputException(sprintf(
                'Invalid members count %s',
                count($aExplodedInput)
            ));
        }

        // Get members
        $sPayload = base64_decode($aExplodedInput[0]);
        $sSignature = base64_decode($aExplodedInput[1]);

        // Check signature
        if ($sSignature !== static::signPayload($sPayload, $sKey)) {
            throw new InvalidSignatureException(sprintf(
                'Invalid signature %s',
                $sSignature
            ));
        }

        // Unbuild payload
        $aPayload = static::unbuildPayload($sPayload);

        // Invalid payload
        if (is_null($aPayload)) {
            throw new InvalidPayloadException(sprintf(
                'Payload <%s> is a malformed JSON',
                $sPayload
            ));
        }

        // Check required keys
        $aRequiredKeys = array_merge(
            $aRequiredKeys,
            ['timestamp', 'nonce']
        );
        try {
            ExtendedArray::checkRequiredKeys($aPayload, $aRequiredKeys);
        } catch (\Exception $oException) {
            throw new InvalidPayloadException($oException->getMessage());
        }

        // Check time validity
        $iTimestamp = intval($aPayload['timestamp']);
        if ($iValidityDuration > 0 && time() > $iTimestamp + $iValidityDuration) {
            throw new InvalidPayloadException(sprintf(
                'Timestamp <%s> has expired',
                $iTimestamp
            ));
        } elseif ($iTimestamp > time()) {
            throw new InvalidPayloadException(sprintf(
                'Timestamp <%s> is in the future',
                $iTimestamp
            ));
        }

        // Return
        unset($aPayload['timestamp']);
        unset($aPayload['nonce']);
        return $aPayload;
    }
}