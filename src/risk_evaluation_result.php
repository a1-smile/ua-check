<?php

/**
 * UA check の計算結果を保存するクラスを定義します。
 * @package student
 * 
 */
class RiskEvaluationResult {
    /**
     * @var int risk scores
     */
    private int   $scoreForSession;
    private int   $scoreForIp;

    // result of AccessDecision statuses
    private int   $accessDecision;

    // AccessDecision statuses

    const int ALLOW            = 1;
    const int REQUIRE_CAPTCHA  = 2;
    const int STOP_MOMENTARY = 3;
    const int LOGOUT           = 4;

    // security level
    private int   $securityLevel;

    const int LEVEL_LOW      =1;
    const int LEVEL_MEDIUM   =2;    
    const int LEVEL_HIGH     =3;
    const int LEVEL_CRITICAL =4;


//     $securityLevel セキュリティレベル
//  SecurityExceptionのセキュリティーレベル
//  と対応させる。
// const LEVEL_LOW      =1;
// SecurityException::LEVEL_LOW

// const LEVEL_MEDIUM   =2;
// SecurityException::LEVEL_MEDIUM

// const LEVEL_HIGH     =3;
// SecurityException::LEVEL_HIGH

// const LEVEL_CRITICAL =4;
// SecurityException::LEVEL_CRITICAL


    // Risk thresholds
    const RISK_THRESHOLD_FOR_CAPTCHA        = 3;
    const RISK_THRESHOLD_FOR_MOMENTARY_STOP = 5;
    const RISK_THRESHOLD_FOR_LOGOUT         = 10;


    /**
     * コンストラクタ
     * 
     * @param int  $ScoreForSession risk score
     * @param int  $ScoreForIp      risk score
     */
    public function __construct(int $scoreForSession, int $scoreForIp) {
        $this->scoreForSession = $scoreForSession;
        $this->scoreForIp      = $scoreForIp;

        $this->accessDecision = 
        $this->calculateAccessDecision(
            $this->scoreForSession, 
            $this->scoreForIp);

        $this->securityLevel = $this->getSecurityLevel();


    }

    /**
     * $accessDecisionを計算します。
     * 
     * @return int $accessDecision
     */
    private function calculateAccessDecision(int $scoreForSession, int $scoreForIp): int {
        // 最大スコアを取得
        $maxScore = max($scoreForSession, $scoreForIp);


        if ($maxScore >= 
            self::RISK_THRESHOLD_FOR_LOGOUT) {

            $this->accessDecision = 
            self::LOGOUT;

        } elseif ($maxScore >= 
            self::RISK_THRESHOLD_FOR_MOMENTARY_STOP) {

            $this->accessDecision = 
            self::STOP_MOMENTARY;

        } elseif ($maxScore >= 
            self::RISK_THRESHOLD_FOR_CAPTCHA) {

            $this->accessDecision = 
            self::REQUIRE_CAPTCHA;

        } else {

            $this->accessDecision = 
            self::ALLOW;
        }

        return $this->accessDecision;
    }

    public function getSecurityLevel(): int {
        // $this->accessDecisionはコンストラクターで計算済み
        
    switch ($this->accessDecision) {
        case self::ALLOW:
            $this->securityLevel = 
            self::LEVEL_LOW;
            break;
        case self::REQUIRE_CAPTCHA:
            $this->securityLevel = 
            self::LEVEL_MEDIUM;
            break;
        case self::STOP_MOMENTARY:
            $this->securityLevel = 
            self::LEVEL_HIGH;
            break;
        case self::LOGOUT:
            $this->securityLevel = 
            self::LEVEL_CRITICAL;
            break;
            default:
            throw new Exception("Invalid access decision");
        }
        
        return $this->securityLevel;
    }
    
    public function getAccessDecision(): int {
        return $this->calculateAccessDecision($this->scoreForSession, $this->scoreForIp);
    }

    // getter for $scoreForSession
    public function getScoreForSession(): int {
        return $this->scoreForSession;
        }
        
    // getter for $scoreForIp
    public function getScoreForIp(): int {
        return $this->scoreForIp;
    }

}