<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Request;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    private $tokenTTL = 3600;

    public function makeCrypt(Request $request){
        $dataCardArr = $request->input();

        if (isset($dataCardArr['pan']) && $this->isCardNumberValid($dataCardArr['pan']) == false){
            Log::error('Incorrect number');
            return response()->json(['message' => 'Incorrect number'], 400);
        }

        if (isset($dataCardArr['cvc']) && preg_match('/^(\d){3}$/', $dataCardArr['cvc']) != 1){
            Log::error('Incorrect CVC code');
            return response()->json(['message' => 'Incorrect CVC code'], 400);
        }

        if (isset($dataCardArr['cardholder']) && is_string($dataCardArr['cardholder']) != 1){
            Log::error('Incorrect Cardholder value');
            return response()->json(['message' => 'Incorrect Cardholder value'], 400);
        }

        if (isset($dataCardArr['expire']) && preg_match('/^(\d){2}\/(\d){2}$/', $dataCardArr['expire']) != 1){
            Log::error('Incorrect expire date');
            return response()->json(['message' => 'Incorrect expire date'], 400);
        }

        $dataCardArr['tokenExpire'] = time() + $this->tokenTTL;

        // Save Private Key
        $privkey = openssl_pkey_new();
        openssl_pkey_export_to_file($privkey, '/etc/ssl/certs/privatetestkey.pem');

        //Save Public Key
        $dn = array(
            "countryName" => "RU",
            "stateOrProvinceName" => "Moscow",
            "localityName" => "test1",
            "organizationName" => "test2",
            "organizationalUnitName" => "test3",
            "commonName" => "www.test.com",
            "emailAddress" => "qwe@qwe.com"
        );
        $cert = openssl_csr_new($dn, $privkey);
        $cert = openssl_csr_sign($cert, null, $privkey, 365);
        openssl_x509_export_to_file($cert, '/etc/ssl/certs/publictestkey.pem');


        $isValid = openssl_public_encrypt (json_encode($dataCardArr), $crypted , file_get_contents('/etc/ssl/certs/publictestkey.pem'),OPENSSL_PKCS1_PADDING);

        if($isValid){
            $dataCardCrypt = base64_encode($crypted);
            $panResponse = substr($dataCardArr['pan'], 0, 4) . ' .... ' . substr($dataCardArr['pan'], -4);
            $tokenResponse = substr($dataCardCrypt, 0, 8) . ' .... ' . substr($dataCardCrypt, -8);
            $result['pan'] = $panResponse;
            $result['token'] = $tokenResponse;

            Log::info(response()->json($result, 200));
            return response()->json($result, 200);
        }
        else{
            Log::error(response()->json(['message' => 'Internal error'], 500));
            return response()->json(['message' => 'Internal error'], 500);
        }
    }

    function isCardNumberValid($s) {
        // оставить только цифры
        $s = strrev(preg_replace('/[^\d]/','',$s));

        // вычисление контрольной суммы
        $sum = 0;
        for ($i = 0, $j = strlen($s); $i < $j; $i++) {
            // использовать четные цифры как есть
            if (($i % 2) == 0) {
                $val = $s[$i];
            } else {
                // удвоить нечетные цифры и вычесть 9, если они больше 9
                $val = $s[$i] * 2;
                if ($val > 9)  $val -= 9;
            }
            $sum += $val;
        }

        // число корректно, если сумма равна 10
        return (($sum % 10) == 0);
    }
}
