<?php

/**
 +-------------------------------------------------------------------------+
 | Mail_mime wrapper for the Enigma Plugin                                 |
 |                                                                         |
 | Copyright (C) 2010-2015 The Roundcube Dev Team                          |
 |                                                                         |
 | Licensed under the GNU General Public License version 3 or              |
 | any later version with exceptions for skins & plugins.                  |
 | See the README file for a full license statement.                       |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | Author: Aleksander Machniak <alec@alec.pl>                              |
 |         Kyle Francis <kyle@linuxtoolbox.ninja>                          |
 +-------------------------------------------------------------------------+
*/

class enigma_mime_message extends Mail_mime
{
    const PGP_SIGNED      = 1;
    const PGP_ENCRYPTED   = 2;
    const SMIME_SIGNED    = 3;
    const SMIME_ENCRYPTED = 4;

    protected $type;
    protected $message;
    protected $body;
    protected $signature;
    protected $encrypted;


    /**
     * Object constructor
     *
     * @param Mail_mime Original message
     * @param int       Output message type
     */
    function __construct($message, $type)
    {
        $this->message = $message;
        $this->type    = $type;

        // clone parameters
        foreach (array_keys($this->build_params) as $param) {
            $this->build_params[$param] = $message->getParam($param);
        }

        // clone headers
        $this->headers = $message->headers();
/*
        if ($message->getParam('delay_file_io')) {
            // use common temp dir
            $temp_dir    = $this->config->get('temp_dir');
            $body_file   = tempnam($temp_dir, 'rcmMsg');
            $mime_result = $message->saveMessageBody($body_file);

            if (is_a($mime_result, 'PEAR_Error')) {
                self::raise_error(array('code' => 650, 'type' => 'php',
                    'file' => __FILE__, 'line' => __LINE__,
                    'message' => "Could not create message: ".$mime_result->getMessage()),
                    true, false);
                return false;
            }

            $msg_body = fopen($body_file, 'r');
        }
        else {
*/
            // \r\n is must-have here
            $this->body = $message->get() . "\r\n";
/*
        }
*/
    }

    /**
     * Check if the message is multipart (requires PGP/MIME)
     *
     * @return bool True if it is multipart, otherwise False
     */
    public function isMultipart()
    {
        return $this->message instanceof enigma_mime_message
            || $this->message->isMultipart() || $this->message->getHTMLBody();
    }

    /**
     * Get e-mail address of message sender
     *
     * @return string Sender address
     */
    public function getFromAddress()
    {
        // get sender address
        $headers = $this->message->headers();
        $from    = rcube_mime::decode_address_list($headers['From'], 1, false, null, true);
        $from    = $from[1];

        return $from;
    }

    /**
     * Get recipients' e-mail addresses
     *
     * @return array Recipients' addresses
     */
    public function getRecipients()
    {
        // get sender address
        $headers = $this->message->headers();
        $to      = rcube_mime::decode_address_list($headers['To'], null, false, null, true);
        $cc      = rcube_mime::decode_address_list($headers['Cc'], null, false, null, true);
        $bcc     = rcube_mime::decode_address_list($headers['Bcc'], null, false, null, true);

        $recipients = array_unique(array_merge($to, $cc, $bcc));
        $recipients = array_diff($recipients, array('undisclosed-recipients:'));

        return $recipients;
    }

    /**
     * Get original message body, to be encrypted/signed
     *
     * @return string Message body
     */
    public function getOrigBody()
    {
        $_headers = $this->message->headers();
        $headers  = array();

        if ($_headers['Content-Transfer-Encoding']) {
            $headers[] = 'Content-Transfer-Encoding: ' . $_headers['Content-Transfer-Encoding'];
        }
        $headers[] = 'Content-Type: ' . $_headers['Content-Type'];

        return implode("\r\n", $headers) . "\r\n\r\n" . $this->body;
    }

    /**
     * Register signature attachment
     *
     * @param string Signature body
     */
    public function addSignature($body)
    {
        $this->signature = $body;
        // Reset Content-Type to be overwritten with valid boundary
        unset($this->headers['Content-Type']);
        // get a new boundary for SMIME signed since the signature will be the
        //     outermost MIME wrapper
        if ($this->type == self::SMIME_SIGNED)
            unset($this->build_params['boundary']);
    }

    /**
     * Register encrypted body
     *
     * @param string Encrypted body
     */
    public function setPGPEncryptedBody($body)
    {
        $this->encrypted = $body;
        // Reset Content-Type to be overwritten with valid boundary
        unset($this->headers['Content-Type']);
    }

    /**
     * Builds the multipart message.
     *
     * @param array    $params    Build parameters that change the way the email
     *                            is built. Should be associative. See $_build_params.
     * @param resource $filename  Output file where to save the message instead of
     *                            returning it
     * @param boolean  $skip_head True if you want to return/save only the message
     *                            without headers
     *
     * @return mixed The MIME message content string, null or PEAR error object
     */
    public function get($params = null, $filename = null, $skip_head = false)
    {
        if (isset($params)) {
            while (list($key, $value) = each($params)) {
                $this->build_params[$key] = $value;
            }
        }

        $this->checkParams();

        if ($this->type == self::PGP_SIGNED) {
            $params = array(
                'preamble'     => "This is an OpenPGP/MIME signed message (RFC 4880 and 3156)",
                'content_type' => "multipart/signed; micalg=pgp-sha1; protocol=\"application/pgp-signature\"",
                'eol'          => $this->build_params['eol'],
            );

            $message = new Mail_mimePart('', $params);

            if (!empty($this->body)) {
                $headers = $this->message->headers();
                $params  = array('content_type' => $headers['Content-Type']);

                if ($headers['Content-Transfer-Encoding']) {
                    $params['encoding'] = $headers['Content-Transfer-Encoding'];
                }

                $message->addSubpart($this->body, $params);
            }

            if (!empty($this->signature)) {
                $message->addSubpart($this->signature, array(
                    'filename'     => 'signature.asc',
                    'content_type' => 'application/pgp-signature',
                    'disposition'  => 'attachment',
                    'description'  => 'OpenPGP digital signature',
                ));
            }
        }
        else if ($this->type == self::PGP_ENCRYPTED) {
            $params = array(
                'preamble'     => "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)",
                'content_type' => "multipart/encrypted; protocol=\"application/pgp-encrypted\"",
                'eol'          => $this->build_params['eol'],
            );

            $message = new Mail_mimePart('', $params);

            $message->addSubpart('Version: 1', array(
                    'content_type' => 'application/pgp-encrypted',
                    'description'  => 'PGP/MIME version identification',
            ));

            $message->addSubpart($this->encrypted, array(
                    'content_type' => 'application/octet-stream',
                    'description'  => 'PGP/MIME encrypted message',
                    'disposition'  => 'inline',
                    'filename'     => 'encrypted.asc',
            ));
        } else if ($this->type == self::SMIME_SIGNED) {
            $params = array(
                'preamble'      => "This is an S/MIME signed message",
                'content_type'  => "multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=\"sha-256\"",
                'eol'           => $this->build_params['eol'],
            );

            $message = new Mail_mimePart('', $params);

            if (!empty($this->body)) {
                $headers = $this->message->headers();
                $params  = array('content_type' => $headers['Content-Type']);

                if ($headers['Content-Transfer-Encoding']) {
                    $params['encoding'] = $headers['Content-Transfer-Encoding'];
                }

                $message->addSubpart($this->body, $params);
            }

            if (!empty($this->signature)) {
                $message->addSubpart($this->signature, array(
                    'filename'     => 'smime.p7s',
                    'content_type' => 'application/pkcs7-signature',
                    'disposition'  => 'attachment',
                    'encoding'     => 'base64',
                    'description'  => 'S/MIME Cryptographic Signature',
                ));
            }

        } else if ($this->type == self::SMIME_ENCRYPTED) {
            $params = array(
                'content_type'  => "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=\"enveloped-data\"",
                'encoding'      => "base64",
                'disposition'   => 'attachment; filename="smime.p7m"',
                'filename'      => 'smime.p7m',
                'eol'           => $this->build_params['eol'],
            );
        }

        // Use saved boundary
        if (!empty($this->build_params['boundary'])) {
            $boundary = $this->build_params['boundary'];
        }
        else {
            $boundary = null;
        }

        // Write output to file
        if ($filename) {
            // Append mimePart message headers and body into file
            $headers = $message->encodeToFile($filename, $boundary, $skip_head);
            if ($this->isError($headers)) {
                return $headers;
            }
            $this->headers = array_merge($this->headers, $headers);
            return null;
        }
        else {
            if (gettype($message) == 'NULL')
                return $this->body;

            $output = $message->encode($boundary, $skip_head);
            if ($this->isError($output)) {
                return $output;
            }
            $this->headers = array_merge($this->headers, $output['headers']);
            /* update the boundary build_param or else multipart messages will
               have the inner boundary and not the outer boundary making them
               unreadable to most MUA's */
            if ($boundary == null) {
                preg_match('/boundary="([^"]+)"/', $this->headers['Content-Type'], $m);
                $this->build_params['boundary'] = $m[1];
            }

            return $output['body'];
        }
    }

    /**
     * Get Content-Type and Content-Transfer-Encoding headers of the message
     *
     * @return array Headers array
     */
    protected function contentHeaders()
    {
        $this->checkParams();

        $eol = $this->build_params['eol'] ?: "\r\n";

        // multipart message: and boundary
        if (!empty($this->build_params['boundary'])) {
            $boundary = $this->build_params['boundary'];
        }
        else if (!empty($this->headers['Content-Type'])
            && preg_match('/boundary="([^"]+)"/', $this->headers['Content-Type'], $m)
        ) {
            $boundary = $m[1];
        }
        else {
            $boundary = '=_' . md5(rand() . microtime());
        }

        $this->build_params['boundary'] = $boundary;

        if ($this->type == self::PGP_SIGNED) {
            $headers['Content-Type'] = "multipart/signed; micalg=pgp-sha1;$eol"
                ." protocol=\"application/pgp-signature\";$eol"
                ." boundary=\"$boundary\"";
        }
        else if ($this->type == self::PGP_ENCRYPTED) {
            $headers['Content-Type'] = "multipart/encrypted;$eol"
                ." protocol=\"application/pgp-encrypted\";$eol"
                ." boundary=\"$boundary\"";
        }
        else if ($this->type == self::SMIME_SIGNED) {
            $headers['Content-Type'] = "multipart/signed; micalg=\"sha-256\";$eol"
                ." protocol=\"application/x-pkcs7-signature\";$eol"
                ." boundary=\"$boundary\"";
        } else if ($this->type == self::SMIME_ENCRYPTED) {
            $headers['Content-Type'] = "application/pkcs7-mime; name=\"smime.p7m\";$eol"
                ." smime-type=enveloped-data";
            $headers['Content-Transfer-Encoding'] = "base64";
        }

        return $headers;
    }
}
