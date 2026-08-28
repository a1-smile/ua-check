<?php


// $contents = [
//         'session_id' => 'abc123',
//         'ip_address' => '192.168.0.1',
//         'simple_ua' => 'Mozilla/5.0',
//         'is_no_ua' => 0,
//         'is_ua_mismatch' => 0,
//         'recaptcha_solved' => 0
//     ];  

/* RequestContentImplementation が必要です。
simple ua を求めるときにRequestContentImplementationの静的メソッドを使用します。 */
    class MockRequestContent1 implements RequestContent {


        //  以下の実装が追加で必要です。（未実装）
        // public function getSessionId(): string;
        // public function getIpAddress(): string;



            // private string $sessionId;
            // private string $ipAddress;
            // private string $simpleUa;
        private int    $isNoUa;
        private int    $isUaMismatch;
        private int    $recaptchaSolved;
        private string $sessionId;
        private string $ipAddress;
        private string $simpleUa;
        private string $currentSimpleUa;
        private string $userAgent;

        public function __construct(array $content) {
            // $this->sessionId = $content['session_id'];
            // $this->ipAddress = $content['ip_address'];
            // $this->simpleUa = $content['simple_ua'];
            $this->isNoUa = $content['is_no_ua'];
            $this->isUaMismatch = $content['is_ua_mismatch'];
            $this->recaptchaSolved = $content['recaptcha_solved'];
            $this->sessionId = $content['session_id'] ?? '';
            $this->ipAddress = $content['ip_address'] ?? '';
            $this->simpleUa = $content['simple_ua'] ?? '';
            $this->userAgent = $content['user_agent'] ?? '';

            $this->currentSimpleUa = RequestContentImplementation::makeSimpleUa($this->userAgent); 

        }

        // public function getSessionId(): string {
        //     return $this->sessionId;
        // }

        // public function getIpAddress(): string {
        //     return $this->ipAddress;
        // }

        // public function getSimpleUa(): string {
        //     return $this->simpleUa;
        // }

        public function getIsNoUa(): int {
            return $this->isNoUa;
        }

        public function getIsUaMismatch(): int {
            return $this->isUaMismatch;
        }

        public function getRecaptchaSolved(): int {
            return $this->recaptchaSolved;
        }

        public function getSessionId(): string {
            return $this->sessionId;
        }

        public function getIpAddress(): string {
            return $this->ipAddress;
        }

        public function getSimpleUa(): string {
            return $this->simpleUa;
        }

            //  getter of $currentSimpleUa
    public function getCurrentSimpleUa(): string
    {
        return $this->currentSimpleUa;
    }

    }
    
    
