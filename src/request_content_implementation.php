<?php

class RequestContentImplementation implements RequestContent
{

    // interface の実装として、必須のメソッドは３つです。
    	// public function getIsNoUa(): int{}

        // public function getIsUaMismatch(): int{}

        // public function getRecaptchaSolved(): int{}

    // プロパティ
    // private $userAgent; 関数内で定義してもいいですが、
    // プロパティとして定義しておくと便利です。
    private string $userAgent;
    // private $firstSimpleUa;
    private string $currentSimpleUa;

    // reCAPTCHA を通過の有効時間（秒）
    const TIME_THRESHOLD = 600; // 10分 時間制限の定義

    // コンストラクタ
    public function __construct()
    {
        // コンストラクタ内で、fetchUa() を呼び出して
        // $this->userAgent にセットしておくと便利です。
        $this->userAgent = $this->fetchUa();
        $this->currentSimpleUa = self::makeSimpleUa($this->userAgent);
    }

        /**
         * UA があるか確認するメソッド
         * ユーザーエージェントがない場合は 1 を返す
         * それ以外の場合は 0 を返すことを想定
         * @return int 1: UAなし, 0: UAあり
         */
    	public function getIsNoUa(): int{
            // ユーザーエージェントがない場合は 1 を返す
            // それ以外の場合は 0 を返すことを想定
            if ($this->userAgent === '') {
                return 1;
            } else {
                return 0;
            }
        }

        public function getIsUaMismatch(): int{
            // ユーザーエージェントが
            // 初回、もしくは前回のアクセスと異なる場合は 1 を返す
            // それ以外の場合は 0 を返すことを想定
            // （実装例）
            $firstSimpleUa = $this->fetchFirstSimpleUa();
            $currentSimpleUa = $this->currentSimpleUa;
            if ($firstSimpleUa !== $currentSimpleUa) {
                return 1;
            } else {
                return 0;
            }
        }

        /**
         * 初回の simplified ユーザーエージェントを取得するメソッド
         * @return string 初回の simplified ユーザーエージェント
         */
        private function fetchFirstSimpleUa(): string{
            // 初回の simplified ユーザーエージェントを server から取得する実装
            // 最初にアクセスすると想定するページ
            // ログインページなどで、session に
            //  $_SESSION['first_simple_ua'] として
            // 保存しておくとことにします。
            if (isset($_SESSION['first_simple_ua'])) {
                return $_SESSION['first_simple_ua'];
            } else {
                // もし session に保存されていなければ、現在の simplified ユーザーエージェントを返す
                return self::makeSimpleUa($this->userAgent);
            }
        }

        public static function makeSimpleUa(string $ua): string{
            // ユーザーエージェントをもとに simplified ユーザーエージェントを作る実装
            // 例えば、ブラウザの種類と OS の種類だけを抜き取るなどの処理になります。
            // ここでは、単純にユーザーエージェント全体を返す例を示します。
                   
            $ua = trim($ua);
            //  単一文の if 文で書くと、以下のようになります。
            //  全バージョンで動作します。
            //  推奨しない現場もあります。
            if ($ua === '') return '';

            // Edge (Chromium) と旧Edge
            if (preg_match('/\bEdg\/(\d+)/i', $ua, $m)) return 'Edge/' . $m[1];
            if (preg_match('/\bEdge\/(\d+)/i', $ua, $m)) return 'Edge/' . $m[1];

            // Opera, SamsungBrowser（Chrome より先に判定）
            if (preg_match('/\bOPR\/(\d+)/i', $ua, $m)) return 'Opera/' . $m[1];
            if (preg_match('/\bSamsungBrowser\/(\d+)/i', $ua, $m)) return 'SamsungBrowser/' . $m[1];

            // Chrome / CriOS
            if (preg_match('/\bChrome\/(\d+)/i', $ua, $m)) return 'Chrome/' . $m[1];
            if (preg_match('/\bCriOS\/(\d+)/i', $ua, $m)) return 'Chrome/' . $m[1];

            // Firefox / FxiOS
            if (preg_match('/\bFirefox\/(\d+)/i', $ua, $m)) return 'Firefox/' . $m[1];
            if (preg_match('/\bFxiOS\/(\d+)/i', $ua, $m)) return 'Firefox/' . $m[1];

            // Safari
            if (preg_match('/\bVersion\/(\d+)/i', $ua, $m) && preg_match('/\bSafari\/\d+/i', $ua)) {
                return 'Safari/' . $m[1];
        }

        // IE
            if (preg_match('/\bMSIE\s(\d+)/i', $ua, $m)) return 'IE/' . $m[1];
            if (stripos($ua, 'Trident/') !== false && preg_match('/\brv:(\d+)/i', $ua, $m)) return 'IE/' . $m[1];

            return 'Unknown';
        }

      
        public function getRecaptchaSolved(): int{
            // reCAPTCHA を通過し、かつ
            // IP アドレスと session id が変化していない場合は 1 を返す
            // それ以外の場合は 0 を返すことを想定
                // 1. フラグが立っているか
            if (empty($_SESSION['recaptcha_passed'])) {
                 return 0;  // recaptcha 通過していないとみなす
            }

            // 1-1. フラグが １かどうかも確認しておく
            if ($_SESSION['recaptcha_passed'] !== 1) {
            // フラグが不正な値ならクリアしておく
                unset(
                $_SESSION['recaptcha_passed'],
                $_SESSION['recaptcha_ip_prefix'],
                $_SESSION['recaptcha_passed_at']
                );
            return 0;  // recaptcha 通過していないとみなす
            }

            // 2. IP プレフィックス が一致するか
            $ipv4_blocks = 2; // IPv4なら上位16ビット（/16）をプレフィックスとする例
            $ipv6_blocks = 3; // IPv6なら上位48ビット（/48）をプレフィックスとする例
            $savedPrefix = 
            $_SESSION['recaptcha_ip_prefix'] ?? '';

            $currentPrefix = 
            get_ip_prefix_for_session(
                $ipv4_blocks, 
                $ipv6_blocks
                );
            if ($savedPrefix !== $currentPrefix) {
            //  フラグをクリアしておく
                unset(
                    $_SESSION['recaptcha_passed'],
                    $_SESSION['recaptcha_ip_prefix'],
                    $_SESSION['recaptcha_passed_at']
                    );  
                return 0;  // recaptcha 通過していないとみなす
            }
            // 3. 有効期限内か
            $solvedAt = 
            $_SESSION['recaptcha_passed_at'] ?? 0;
            $pastTimeFromPassed = time() - $solvedAt; // 経過時間

            // 経過時間が閾値を超えているか
            $isExpired = $pastTimeFromPassed > self::TIME_THRESHOLD;
        if ($isExpired) {
            // 期限切れならフラグもクリア
            unset(
              $_SESSION['recaptcha_passed'],
              $_SESSION['recaptcha_ip_prefix'],
              $_SESSION['recaptcha_passed_at']
              );
            return 0; // recaptcha 通過を失効とみなす
        }
        // すべての条件を満たしている場合は 1 を返す
        // （recaptcha 通過とみなす）
        //  フラグをクリアする。複数回の使用を防止するため。
        unset(
          $_SESSION['recaptcha_passed'],
          $_SESSION['recaptcha_ip_prefix'],
          $_SESSION['recaptcha_passed_at']
          );
    return 1;  // recaptcha 通過とみなす
    }



    // UA を取得するメソッド
        private function fetchUa(): string{
            // UA がセットされていたら
            // $userAgent にセットして返す
            // そうでなければ空文字を返す
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $userAgent = $_SERVER['HTTP_USER_AGENT'];
                return $userAgent;
            } else {
                return '';
            }

        }



    public function getSessionId(): string
    {
        // セッションIDを安全に取得する実装
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $sessionId = session_id();
        // sessionId をハッシュ化
        return hash('sha256', $sessionId);
    }

    public function getIpAddress(): string
    {
        // ユーザーのIPアドレスを正確に取得する実装
        // ip address があるかを確認する,なければ例外を投げる
        // RuntimeException が適切なケース
        // 実行環境の問題で、コードだけでは防げない
        if (!isset($_SERVER['REMOTE_ADDR'])) {
            throw new RuntimeException('IP address not found');
        }

        //  ip address が空文字でないかも確認する,空文字なら例外を投げる
        if (empty($_SERVER['REMOTE_ADDR'])) {
            throw new RuntimeException('IP address is empty');
        }
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        return $ipAddress;
    }

    //  getter of $currentSimpleUa
    public function getCurrentSimpleUa(): string
    {
        return $this->currentSimpleUa;
    }

}
