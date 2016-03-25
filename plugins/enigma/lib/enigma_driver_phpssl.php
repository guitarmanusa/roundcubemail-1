<?php

/**
 +-------------------------------------------------------------------------+
 | S/MIME driver for the Enigma Plugin                                     |
 |                                                                         |
 | Copyright (C) 2010-2015 The Roundcube Dev Team                          |
 |                                                                         |
 | Licensed under the GNU General Public License version 3 or              |
 | any later version with exceptions for skins & plugins.                  |
 | See the README file for a full license statement.                       |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | Author: Aleksander Machniak <alec@alec.pl>                              |
 +-------------------------------------------------------------------------+
*/

class enigma_driver_phpssl extends enigma_driver
{
    private $rc;
    private $homedir;
    private $user;
    private $trusted_CAs;

    function __construct($user)
    {
        $rcmail = rcmail::get_instance();
        $this->rc   = $rcmail;
        $this->user = $user;
    }

    /**
     * Driver initialization and environment checking.
     * Should only return critical errors.
     *
     * @return mixed NULL on success, enigma_error on failure
     */
    function init()
    {
        $homedir = $this->rc->config->get('enigma_smime_homedir', INSTALL_PATH . 'plugins/enigma/home');
        $this->trusted_CAs = $this->rc->config->get('enigma_root_cas_location', "/etc/ssl/certs");
 
        if (!$homedir)
            return new enigma_error(enigma_error::INTERNAL,
                "Option 'enigma_smime_homedir' not specified");
        if (!$this->trusted_CAs)
            return new enigma_error(enigma_error::INTERNAL,
                "Option 'enigma_root_cas_location' not specified");

        // check if homedir exists (create it if not) and is readable
        if (!file_exists($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Certificate directory doesn't exists: $homedir");
        if (!is_writable($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Certificate directory isn't writeable: $homedir");

        $homedir = $homedir . '/' . $this->user;

        // check if user's homedir exists (create it if not) and is readable
        if (!file_exists($homedir))
            mkdir($homedir, 0700);

        if (!file_exists($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to create certificate directory: $homedir");
        if (!is_writable($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to write to certificate directory: $homedir");

        //make directory for user trusted CA certificates
        $ca_dir = $homedir . '/ca_certs';

        if (!file_exists($ca_dir))
            mkdir($ca_dir, 0700);
        if (!file_exists($ca_dir))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to create CA directory: $ca_dir");
        if (!is_writable($ca_dir))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to write to CA directory: $ca_dir");

        //make directory for certificates received via signed messages
        //so that you can send encrypted emails later
        $user_certs = $homedir . '/user_certs';

        if (!file_exists($user_certs))
            mkdir($user_certs, 0700);
        if (!file_exists($user_certs))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to create directory for received certificates: $user_certs");
        if (!is_writable($user_certs))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to write to directory for received certificates: $user_certs");

        $this->homedir = $homedir;
        
    }

    function encrypt($text, $keys)
    {
    }

    /**
     * Message decryption.
     *
     * @param string Input filename to be decrypted
     * @param array  Keys to use for decryption
     * @param string Output filename to put decrypted text
     *
     * @return mixed True if decrypt successful, enigma_error if failed
    **/
    function decrypt($infilename, $keys = array(), $outfilename = '')
    {
        if(empty($keys) || is_null($keys)) {
            if(file_exists($this->homedir."/user.pem")) {
                $user_certs = file_get_contents($this->homedir."/user.pem");
                $keys = explode("-----END CERTIFICATE-----", $user_certs);
                $keys[0] .= "-----END CERTIFICATE-----\n";
            } else {
                return new enigma_error(enigma_error::INTERNAL, "No certificate for user found.");
            }
        }
        $result = openssl_pkcs7_decrypt($infilename, $outfilename, $keys[0], $keys[1]);

        if ($result === true) {
            return true;
        } else {
            return new enigma_error(enigma_error::INTERNAL, "Failed to decrypt message.");
        }
    }

    function sign($text, $key, $passwd, $mode = null)
    {
    }

    /**
     * Signature verification.
     *
     * @param string Filename of file containing full MIME Message body (including headers)
     * @param string Signature, if message is of type S/MIME and body doesn't contain it
     *
     * @return mixed Signature information (enigma_signature) or enigma_error
     */
    function verify($text, $signature='')
    {
        //store the cert if we don't have it yet
        //save file as <email address> for easy lookup /From: .*<(.*\@.*)>/
        $cert_file = $this->homedir . "/user_certs/";
        $body = file_get_contents($text);
        preg_match("/^From: .*<(.*\@.*)>/m", $body, $email);
        $cert_file .= $email[1];

        // try with certificate verification
        $sig      = openssl_pkcs7_verify($text, 0, $cert_file, array($this->trusted_CAs,$this->homedir.'/ca_certs'));
        chmod($cert_file, 0600);
        $validity = true;

        if ($sig !== true) {
            // try without certificate verification
            $sig      = openssl_pkcs7_verify($msg_file, PKCS7_NOVERIFY, $cert_file);
            $validity = enigma_error::UNVERIFIED;
        }

        if ($sig === true) {
            $sig = $this->parse_sig_cert($cert_file, $validity);
        }
        else {
            $errorstr = $this->get_openssl_error();
            $sig = new enigma_error(enigma_error::INTERNAL, $errorstr);
        }

        return $sig;
    }

    public function import($cert_store, $isfile=false, $password='')
    {
        //TODO should only be importing PKCS #12 store with user's Cert/PKey
        //  stored in plugins/enigma/home/<username>/user.pem
        //or additional trusted Root CA certificates

        $ca_dir = $this->homedir . '/ca_certs';

        if ($isfile && !$cert_store = file_get_contents($cert_store))
            return new enigma_error(enigma_error::INTERNAL,
                "Error: Unable to read the cert file.");
 
        if (openssl_pkcs12_read($cert_store, $cert_info, $password)) {
            $results = array('imported' => 0, 'unchanged' => 0);

            //check that the private key in the p12 is the correct private key for the cert
            if (!openssl_x509_check_private_key($cert_info['cert'], $cert_info['pkey'])) {
                return new enigma_error(enigma_error::INTERNAL,
                    "Private key <-> Certificate mismatch");
            } else {
                $pubcert = openssl_x509_parse($cert_info['cert']);
                $can_sign = false;
                $can_encrypt = false;
    
                //check that cert is for email address of user
                if ($pubcert['subject']['emailAddress'] == $this->user) {
                    //check that cert can be used for SMIME signing and encrypting
                    foreach ($pubcert['purposes'] as $purpose) {
                        if ($purpose[2] == "smimesign")
                            $can_sign = true;
                        if ($purpose[2] == "smimeencrypt")
                            $can_encrypt = true;
                    }
                    if ($can_sign && $can_encrypt) {
                        if (file_exists($this->homedir."/user.pem")) {
                            $existing_cert = file_get_contents($this->homedir."/user.pem");
                            $existing_cert = openssl_x509_parse($existing_cert);
                            if($existing_cert['cert'] == $pubcert['cert']) {
                                $results['unchanged'] += 1;
                            }
                        } else {
                            file_put_contents($this->homedir."/user.pem", $cert_info['cert'].$cert_info['pkey']);
                            chmod($this->homedir."/user.pem", 0700);
                            $results['imported'] += 1;  //not counting private key, personal preference...
                        }
                    } else {
                        return new enigma_error(enigma_error::INTERNAL,
                            "Certificate is not valid for SMIME signing and encrypting!");
                    }
                }
            }

            //only process Extracerts if there are any
            if (is_array($cert_info['extracerts']) && !empty($cert_info['extracerts'])) { 
                //name file as hash (just like c_rehash would do)
                $conflicts = array();

                foreach ($cert_info['extracerts'] as $extracert) {
                    $repeat = false;
                    //first file in directory with hash
                    $extracert_parse = openssl_x509_parse($extracert);

                    if (!file_exists($ca_dir . "/" . $extracert_parse['hash'])) {
                        file_put_contents($ca_dir . "/" . $extracert_parse['hash'], $extracert);
                        $results['imported'] += 1;
                    } else {
                        $postfix = "";
                        $cert_filename = $ca_dir . "/" . $extracert_parse['hash'] . $postfix;

                        //jump to the largest HHHHHHHH.d (if known)
                        if (in_array($conflicts[$extracert_parse['hash']]))
                            $postfix = "." . $conflicts[$extracert_parse['hash']];
                        $conflict = file_get_contents($ca_dir . "/" . $extracert_parse['hash'] . $postfix);

                        while(file_exists($cert_filename)) {
                            //compare x509 fingerprints (SHA1)
                            if (openssl_x509_fingerprint($conflict) != openssl_x509_fingerprint($extracert)) {
                                if (!in_array($conflicts[$extracert_parse['hash']]))
                                    $conflicts[$extracert_parse['hash']] = 0;
                                else
                                    $conflicts[$extracert_parse['hash']] += 1;
                                $cert_filename = $ca_dir . "/" . $extracert_parse['hash'] . "." . $conflicts[$extracert_parse['hash']];
                            } else {
                                $results['unchanged'] += 1;
                                $repeat = true;
                                break;
                            }
                        }
                        //write file
                        if(!$repeat) {
                            file_put_contents($cert_filename,$extracert);
                            $results['imported'] += 1;
                        }
                    }
                }
            }
            return $results;
        } else {
            $error = "";
            while ($msg = openssl_error_string())
                $error .= $msg;
            return new enigma_error(enigma_error::INTERNAL,
                $error);
                //"Unable to parse PKCS #12 certificate store: Incorrect password.");
        }
    }

    public function export($key)
    {
    }

    /**
     * Certificate listing.
     *
     * @param string Optional pattern for key ID, user ID or fingerprint
     *
     * @return mixed Array of enigma_key objects or enigma_error
     */
    public function list_keys($pattern='')
    {
        //Open file
        $certchain = file_get_contents($this->homedir."/user.pem", "r");

        if (!$certchain)
            //TODO return enigma error
            return false; 

        preg_match($certchain, $certs);
        $results = array();

        //For each in array(certs)
        foreach ( $certs as $cert ) {
            //openssl_x509_parse
            $cert_attribs = openssl_x509_parse($cert);
                //pull out identifiers, store to array
        }
        //return array
        return results;
    }

    public function get_key($keyid)
    {
    }

    public function gen_key($data)
    {
    }

    public function delete_key($keyid)
    {
    }

    public function delete_privkey($keyid)
    {
    }

    public function delete_pubkey($keyid)
    {
    }

    private function get_openssl_error()
    {
        $tmp = array();
        while ($errorstr = openssl_error_string()) {
            $tmp[] = $errorstr;
        }

        return join("\n", array_values($tmp));
    }

    private function ssl_errcode($output) {
        $results = array();

        if ($output !== true) {
            while ($errmsg = $this->get_openssl_error()) {
                if (preg_match('/^error:([^:]+):(.*)$/', $errmsg, $errcode)) {
                    switch ($errcode[1]) {
                        case '2107C080': 
                            $nocert = true;
                            break;
                        case '04091068':
                            $signerr = true;
                            break;
                        case '????????':   // It is necessary to clarify the error code when expired or incorrect certificate
                            $certbad = true;
                            break;
                        case '21075075':
                            $issbad = true;
                            break;
                        default:
                            $error = true;
                    }
                }
                else {
                    $error = true;
                }

                $results[] = $errmsg;
            }
            if ($error || $output === -1) {  
                $r = 'error';
            }
            elseif ($nocert) {
                $r = 'nocert';
            }
            elseif ($signerr) {
                $r = 'signerr';
            }
            elseif ($certbad) {
                $r = 'certbad';
            }
            elseif ($issbad) {
                $r = 'issbad';
            }
            else {
                $r = 'error';   // result is not true without error messages
            }
        }
        else {
            $r = 'ok';
        }
        return array($r,implode("\n",$results));
    }

    /**
     * Converts S/MIME Certificate object into Enigma's key object
     *
     * @param filename /path/to/certificate (PEM format)
     * @param validity boolean
     *
     * @return enigma_key Key object
     */
    private function parse_sig_cert($file, $validity)
    {
        $cert = openssl_x509_parse(file_get_contents($file));

        if (empty($cert) || empty($cert['subject'])) {
            $errorstr = $this->get_openssl_error();
            return new enigma_error(enigma_error::INTERNAL, $errorstr);
        }

        $data = new enigma_signature();

        $data->id          = $cert['hash']; //?
        $data->valid       = $validity;
        $data->fingerprint = $cert['serialNumber'];
        $data->created     = $cert['validFrom_time_t'];
        $data->expires     = $cert['validTo_time_t'];
        $data->name        = $cert['subject']['CN'];
//      $data->comment     = '';
        $data->email       = $cert['subject']['emailAddress'];

        return $data;
    }

    private function get_user_info_from_cert($file)
    {
        $cert     = openssl_x509_parse(file_get_contents($file));
        $sub      = $cert['subject'];   
        $ret      = array();

        if (array_key_exists('emailAddress', $sub)) {
            $ret['email'] = $sub['emailAddress'];
        }

        if (array_key_exists('CN', $sub)) {
            $ret['name'] = $sub['CN'];
        }

        if (array_key_exists('issuer', $cert)) {
            $issuer = $cert['issuer'];
            if (array_key_exists('O', $issuer)) {
                $ret['issuer'] = $issuer['O'];
            }
        }

        // Scan subAltName for email addresses
        if (array_key_exists('extensions', $cert) && array_key_exists('subjectAltName', $cert['extensions'])) {

            $emailAddresses = isset($ret['email'])?array($ret['email']):array();  

            // Not shure that it is correct, but do not drop address in Common Name if it is.            
            foreach (explode(', ', $cert['extensions']['subjectAltName']) as $altName) {
                $parts = explode(':', $altName);
                if ($parts[0] == 'email') {
                    array_push ($emailAddresses, $parts[1]);
                }
            }

            if (count($emailAddresses) > 0) {
                $ret['email'] = $emailAddresses;
            }
        }

        return $ret;
    }
}
