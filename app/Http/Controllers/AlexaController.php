<?php

namespace App\Http\Controllers;

use Error;
use Exception;
use Carbon\Carbon;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use AppExceptions\EchoValidationException;

class AlexaController extends Controller
{

    protected $primaries;
    protected $applicationId;

    public function __construct()
    {
        $this->applicationId = env('ALEXA_SKILL_ID');
        $this->primaries = [
            ['date' => '2020-02-03', 'state' => 'Iowa Caucuses'],
            ['date' => '2020-02-11', 'state' => 'New Hampshire'],
            ['date' => '2020-02-15', 'state' => 'Democratic Nevada Caucus'],
            ['date' => '2020-02-22', 'state' => 'Democratic South Carolina'],
            ['date' => '2020-03-03', 'state' => 'Alabama'],
            ['date' => '2020-03-03', 'state' => 'California'],
            ['date' => '2020-03-03', 'state' => 'Massachusetts'],
            ['date' => '2020-03-03', 'state' => 'North Carolina'],
            ['date' => '2020-03-03', 'state' => 'Oklahoma'],
            ['date' => '2020-03-03', 'state' => 'Tennessee'],
            ['date' => '2020-03-03', 'state' => 'Texas'],
            ['date' => '2020-03-03', 'state' => 'Vermont'],
            ['date' => '2020-03-03', 'state' => 'Virginia'],
            ['date' => '2020-03-07', 'state' => 'Louisiana'],
            ['date' => '2020-03-10', 'state' => 'Republican Hawaii Caucus'],
            ['date' => '2020-03-10', 'state' => 'Idaho'],
            ['date' => '2020-03-10', 'state' => 'Michigan'],
            ['date' => '2020-03-10', 'state' => 'Mississippi'],
            ['date' => '2020-03-10', 'state' => 'Missouri'],
            ['date' => '2020-03-10', 'state' => 'Ohio'],
            ['date' => '2020-03-17', 'state' => 'Arizona'],
            ['date' => '2020-03-17', 'state' => 'Florida'],
            ['date' => '2020-03-17', 'state' => 'Illinois'],
            ['date' => '2020-04-07', 'state' => 'Wisconsin'],
            ['date' => '2020-04-28', 'state' => 'Connecticut'],
            ['date' => '2020-04-28', 'state' => 'Delaware'],
            ['date' => '2020-04-28', 'state' => 'Maryland'],
            ['date' => '2020-04-28', 'state' => 'Pennsylvania'],
            ['date' => '2020-04-28', 'state' => 'Rhode Island'],
            ['date' => '2020-05-05', 'state' => 'Indiana'],
            ['date' => '2020-05-12', 'state' => 'Republican Nebraska'],
            ['date' => '2020-05-12', 'state' => 'West Virginia'],
            ['date' => '2020-05-19', 'state' => 'Arkansas'],
            ['date' => '2020-05-19', 'state' => 'Kentucky'],
            ['date' => '2020-05-19', 'state' => 'Oregon'],
            ['date' => '2020-05-26', 'state' => 'Republican Washington Caucus'],
            ['date' => '2020-06-02', 'state' => 'Montana'],
            ['date' => '2020-06-02', 'state' => 'New Jersey'],
            ['date' => '2020-06-02', 'state' => 'New Mexico'],
            ['date' => '2020-06-02', 'state' => 'South Dakota'],
            ['date' => '2020-06-07', 'state' => 'Democratic Puerto Rico'],
            ['date' => '2020-06-06', 'state' => 'Democratic Washington, DC'],
        ];
    }

    public function getNextPrimary()
    {
        $today = Carbon::today();

        $nextDate = null;

        foreach ($this->primaries as $value) {
            $date = Carbon::parse($value['date']);
            if ($today->lessThanOrEqualTo($date)) {
                $nextDate = $value['date'];
                break;
            }
        }

        $next = collect($this->primaries)
            ->filter(
                function ($value, $key) use ($nextDate) {
                    return $value['date'] == $nextDate;
                }
            );

        $daysUntil = $today->diffForHumans(Carbon::parse($nextDate), 1);

        return "The next primary is in " . $daysUntil . " and is being held in " . $this->arrayImplodeNice($next->pluck('state')->toArray());
    }

    public function getAlexaResponse()
    {
        Log::info(request()->getContent());
        Log::info(json_encode($_SERVER));

        $headers = request()->header();

        try {
            // Validate the request
            $this->validateEchoPayload(request()->getContent(), $headers);
        } catch (EchoValidationException $e) {
            return (new Response(null, 400));
        } catch (Exception $e) {
            Log::info("1");
            Log::info(json_encode(['error' => $e->getMessage(), 'line' => $e->getLine()]));
            return json_encode(['error' => $e->getMessage(), 'line' => $e->getLine()]);
        } catch (Error $e) {
            Log::info("2");
            return json_encode(['error' => $e->getMessage(), 'line' => $e->getLine()]);
        }

        // Respond to the request
        $responseText = $this->getNextPrimary();
        $return = [
            'version' => '1.0.0',
            'response' => [
                'outputSpeech' => [
                    'type' => 'PlainText',
                    'text' => $responseText,
                ],
            ],
            'card' => [
                'type' => 'Simple',
                'title' => 'Next Presidential Primary',
                'content' => $responseText,
            ],
        ];
        Log::info("3");

        return json_encode($return);
    }

    public function logAndDie($logMessage = null, $lineNumber = null)
    {
        if ($lineNumber) {
            Log::info("Line: " . $lineNumber);
        }
        if ($logMessage) {
            Log::info($logMessage);
        }
        throw new EchoValidationException($logMessage);
    }

    public function validateEchoPayload($jsonData, $headers)
    {

        $applicationIdValidation = $this->applicationId;
        $echoServiceDomain = 'echo-api.amazon.com';
        $data = json_decode($jsonData, true);

        Log::info(json_encode($headers));

        // Parse out key variables
        $sessionId = @$data['session']['sessionId'];
        $applicationId = @$data['session']['application']['applicationId'];
        $requestTimestamp = @$data['request']['timestamp'];
        $requestType = $data['request']['type'];

        // Die if applicationId isn't valid
        if ($applicationId != $applicationIdValidation) {
            return $this->logAndDie('Invalid Application id: ' . $applicationId, __LINE__);
        }

        // Check that the Signature Chain URL is not empty
        if (isset($headers['signaturecertchainurl']) === false || empty($headers['signaturecertchainurl']) || empty($headers['signaturecertchainurl'][0])) {
            return $this->logAndDie('Signature Chain URL is empty or missing');
        }

        // Determine if we need to download a new Signature Certificate Chain from Amazon
        $md5pem = md5($headers['signaturecertchainurl'][0]);
        $md5pem = $md5pem . '.pem';

        // If we haven't received a certificate with this URL before, store it as a cached copy
        try {
            $pem = file_get_contents($headers['signaturecertchainurl'][0]);
        } catch (Exception $e) {
            $this->logAndDie('Error fetching signaturecertchainurl (might be malformed URL): ' . $headers['signaturecertchainurl'][0]);
        }

        // Validate proper format of Amazon provided certificate chain url
        // Validate keychainUri is proper (from Amazon)
        $uriParts = parse_url($headers['signaturecertchainurl'][0]);

        if (strcasecmp($uriParts['host'], 's3.amazonaws.com') != 0) {
            return $this->logAndDie('The host for the Certificate provided in the header is invalid', __LINE__);
        }

        if (strpos($uriParts['path'], '/echo.api/') !== 0) {
            return $this->logAndDie('The URL path for the Certificate provided in the header is invalid', __LINE__);
        }

        if (strcasecmp($uriParts['scheme'], 'https') != 0) {
            return $this->logAndDie('The URL is using an unsupported scheme. Should be https', __LINE__);
        }

        if (array_key_exists('port', $uriParts) && $uriParts['port'] != '443') {
            return $this->logAndDie('The URL is using an unsupported https port', __LINE__);
        }

        if (!isset($headers['signature']) || empty($headers['signature']) || empty($headers['signature'][0])) {
            return $this->logAndDie('The signature is missing from headers', __LINE__);
        }

        // Validate certificate chain and signature
        $ssl_check = openssl_verify($jsonData, base64_decode($headers['signature'][0]), $pem, 'sha1WithRSAEncryption');
        if ($ssl_check != 1) {
            return $this->logAndDie(openssl_error_string(), __LINE__);
        }

        // Parse certificate for validations below
        $parsedCertificate = openssl_x509_parse($pem);
        if (!$parsedCertificate) {
            return $this->logAndDie('x509 parsing failed', __LINE__);
        }

        // Check that the domain echo-api.amazon.com is present in the Subject Alternative Names (SANs) section of the signing certificate
        if (strpos($parsedCertificate['extensions']['subjectAltName'], $echoServiceDomain) === false) {
            return $this->logAndDie('subjectAltName Check Failed', __LINE__);
        }

        // Check that the signing certificate has not expired (examine both the Not Before and Not After dates)
        $validFrom = $parsedCertificate['validFrom_time_t'];
        $validTo = $parsedCertificate['validTo_time_t'];
        $time = time();
        if (!($validFrom <= $time && $time <= $validTo)) {
            return $this->logAndDie('certificate expiration check failed', __LINE__);
        }

        // Check the timestamp of the request and ensure it was within the past minute
        if (time() - strtotime($requestTimestamp) > 60) {
            if (isset($headers['testing'])) {
                Log::info('Invalid timestamp, but ignoring in testing mode');
            } else {
                return $this->logAndDie('timestamp validation failure.. Current time: ' . time() . ' vs. Timestamp: ' . $requestTimestamp, __LINE__);
            }
        }
    }

    /*
    Validate that the certificate and signature are valid
     */
    public function validateEchoCertificate($jsonRequest, $signatureUrl, $signature)
    {
        // Get the certificate contents
        $pem = file_get_contents($signatureUrl);
        $echoServiceDomain = 'echo-api.amazon.com';

        // Validate certificate chain and signature
        $ssl_check = openssl_verify($jsonRequest, base64_decode($signature), $pem, 'sha1WithRSAEncryption');
        if ($ssl_check != 1) {
            return (openssl_error_string());
        }
        // Parse certificate for validations below
        $parsedCertificate = openssl_x509_parse($pem);
        if (!$parsedCertificate) {
            return ('x509 parsing failed');
        }
        // Check that the domain echo-api.amazon.com is present in
        // the Subject Alternative Names (SANs) section of the signing certificate
        if (strpos(
            $parsedCertificate['extensions']['subjectAltName'],
            $echoServiceDomain
        ) === false) {
            return ('subjectAltName Check Failed');
        }
        // Check that the signing certificate has not expired
        // (examine both the Not Before and Not After dates)
        $validFrom = $parsedCertificate['validFrom_time_t'];
        $validTo = $parsedCertificate['validTo_time_t'];
        $time = time();
        if (!($validFrom <= $time && $time <= $validTo)) {
            return ('certificate expiration check failed');
        }
        return 1;
    }

    /**
     * Implode an array into a proper comma separated list, like a sentence. This
     * will add "and" (or another penultimate word specified by $ending) before the
     * last item in the list, and uses the Oxford Comma in any list 3 or more items
     * long.
     *
     * @param      array   $array   The array of items to implode (nicely)
     * @param      string  $ending  The penultimate word, which will come before the
     *                              last item in the list. Defaults to "and"
     *
     * @return     string  For arrays of:
     *                       - 3 or more items, the return is a string list
     *                           e.g.    ['dogs','cats','sheep']
     *                           returns "dogs, cats, and sheep"
     *                       - 2 items, no commas are used
     *                           e.g.    ['dogs','cats']
     *                           returns "dogs and cats"
     *                       - 1 item, that item is returned as a string
     *                           e.g.    ['dogs']
     *                           returns "dogs"
     *                     For non-array inputs, the original value is returned;
     *
     */
    public function arrayImplodeNice($array, $ending = 'and')
    {
        $return = "";

        if (!is_array($array)) {
            return $return;
        }

        $countOriginal = count($array);

        if ($countOriginal == 1) {
            return array_shift($array);
        }

        if ($countOriginal == 2) {
            return array_shift($array) . $ending . " " . array_shift($array);
        }

        for ($i = 0; $i < $countOriginal; $i++) {
            if (count($array) >= 2) {
                $return .= array_shift($array) . ", ";
            } elseif (count($array) == 1) {
                $return .= $ending . " " . array_shift($array);
            }
        }

        return $return;
    }
}
