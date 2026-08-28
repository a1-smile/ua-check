<?php
/**
 * UserAgentRiskEvaluator は
 * コンストラクターで
 * インターフェイス
 * RequestContent と
 * UaRepository の実装
 * を受け取り、
 * その情報をもとに
 * ユーザーエージェントの
 * リスク評価を$scoreSessionId と $scoreIp で行います。
 * RiskEvaluationResult クラスを使って
 * リスク評価の結果を＄decisionと＄securityLevelで返します。
 * 
 * プログラムを制御する層つまり、
 * UAチェックの結果を受け取って行われる処理
 * では、
 * $decisionと$securityLevelをもとに
 * 
 * // AccessDecision statuses

  *  const int ALLOW            = 1;
  *  const int REQUIRE_CAPTCHA  = 2;
    *  const int STOP_MOMENTARY = 3;
  *  const int LOGOUT           = 4;

   * // security level
    *private int   $securityLevel;

    *const int LEVEL_LOW      =1;
    *const int LEVEL_MEDIUM   =2;    
    *const int LEVEL_HIGH     =3;
    *const int LEVEL_CRITICAL =4;

 * $decisionがALLOW
 * （１ UserAgentRiskEvaluator::ALLOW）
 * の場合はアクセスを許可し、
 * 処理を続行します。
 * 
 * $decisionがREQUIRE_CAPTCHA
 * （２ UserAgentRiskEvaluator::REQUIRE_CAPTCHA）
 * の場合は例外をスローして、
 * reCAPTCHAページにリダイレクトします。
 * student\recaptcha.php
 * リダイレクト先のページでは、CAPTCHAの入力を要求します。
 * CAPTCHAの入力が成功した場合は、
 * 元のページにリダイレクトします。
 * session に$_SERVER['REQUEST_URI']を
 * 保存しておいて、もとのページにリダイレクトするようにします。
 * 
 * sessionにCAPTCHAを解いたことを記録し、
 * アクセスを許可します。
 * 
 * 
 * $decisionがSTOP_MOMENTARY
 * （３ UserAgentRiskEvaluator::STOP_MOMENTARY）
 * STOP_MOMENTARYの場合は一時的に処理を停止するために。
 * student\stop_momentary.php
 * にリダイレクトします。
 * 
 * $decisionがLOGOUT
 * （４ UserAgentRiskEvaluator::LOGOUT）
 * LOGOUTの場合はログアウトさせます。
 * student\log_out.php
 * 
 * @package student
 */

    //  【今後の課題】
//     推奨される対策
// 減算回数の上限: 
// 一定期間内（例: 24時間）での reCAPTCHA による
// 減算回数に上限を設ける

// 減算幅の段階的縮小: 
// reCAPTCHA による減算を繰り返すほど、
// 減算幅を小さくする（-4 → -2 → -1 → 0）

// フラグの即時消費: recaptcha_solved を
// 1回の evaluate() で使用したら即座に unset する

// スコアの「最高到達点」を記録: 
// 過去のピークスコアを保持し、
// 一定閾値を超えた履歴があるユーザーには減算を制限する

// LOGOUT 閾値（10）に達した場合は reCAPTCHA による回復を不可にする

class UserAgentRiskEvaluator {

    const ACCESS_THRESHOLD_SESSION = 60;
    const ACCESS_THRESHOLD_IP      = 600;

    // reCAPTCHA を通過し場合のスコア減算の値
    const DECREASE_SCORE_SESSION= 4;
    const DECREASE_SCORE_IP = 1;

    //  後述の evaluate() の呼び出しは
    //  複数回行われると整合性が取れなくなる可能性があるため、
    //  一度だけ呼び出して結果を保持するようにしています。
    //  その戻り値を保持するプロパティを定義します。
    private RiskEvaluationResult $riskEvaluationResult;

    private RequestContent $requestContent; // インターフェイス RequestContent の実装
    private UaRepository   $uaRepository;   // インターフェイス UaRepository の実装

    //session id ,ip address は、RequestContent の実装が状態として保持していると想定して、
    //ここでは、取得する必要がないと考えコメントアウトにしています。
    // private string $sessionId; // セッションID
    // private string $ipAddress; // IPアドレス

    private int $previousScoreSession; // セッションIDごとの前回のスコア
    private int $previousScoreIp;      // IPアドレスごとの前回のスコア

    private int $currentScoreSession;
    private int $currentScoreIp;
    // private int $scoreSessionId; // セッションIDごとのスコア
    // private int $scoreIp;        // IPアドレスごとのスコア


    private int $accessCountSession;  // セッションIDごとのアクセス回数
    private int $accessCountIp;       // IPアドレスごとのアクセス回数
    
    private int $isNoUa;  // User-Agentがない場合のフラグ
    private int $isUaMismatch; // User-Agent不一致のフラグ

    private int $isOverThresholdSession; // セッションIDごとのアクセス回数が閾値を超えているか
    private int $isOverThresholdIp;      // IPアドレスごとのアクセス回数が閾値を超えているか

    // DBからのフラグ
    private int $isDecreasedSession; // session ベースのスコアが減少したかどうかのフラグ
    private int $isDecreasedIp;
    // 今回のアクセスでの減算があるかを意味するフラグ
    private int $resultIsDecreasedSession; // session ベースのスコアが減少したかどうかのフラグ
    private int $resultIsDecreasedIp;      // IPベースのスコア

    private int $isNoAnomalySession; // セッションIDに異常がない場合のフラグ
    private int $isNoAnomalyIp;      // IPアドレスに異常がない場合のフラグ

    private int $recaptchaSolved; // reCAPTCHAを解いたかどうかのフラグ

    private int $isSuspiciousAccess; // 疑わしいアクセスかどうかのフラグ

    public function __construct(RequestContent $requestContent, UaRepository $uaRepository) {
        $this->requestContent = $requestContent;
        $this->uaRepository   = $uaRepository;

        // session ID と IPアドレスは、RequestContent の実装が
        // 状態として保持していると想定して、
        // ここでは、取得する必要がないと考えコメントアウトにしています。
        // $this->sessionId = $this->requestContent->getSessionId();
        // $this->ipAddress = $this->requestContent->getIpAddress();

        $this->previousScoreSession = $this->uaRepository->getScoreSession();
        $this->previousScoreIp      = $this->uaRepository->getScoreIp();

        $this->accessCountSession = 
        $this->uaRepository->getAccessCountSession();
        $this->accessCountIp      = 
        $this->uaRepository->getAccessCountIp();
        
        $this->isOverThresholdSession = 
        $this->isOverThreshold($this->accessCountSession,
                                self::ACCESS_THRESHOLD_SESSION);
        $this->isOverThresholdIp = 
        $this->isOverThreshold($this->accessCountIp,
                                self::ACCESS_THRESHOLD_IP);

        $this->isNoUa = 
        $this->requestContent->getIsNoUa();
        $this->isUaMismatch = 
        $this->requestContent->getIsUaMismatch();

        $this->isDecreasedSession = 
        $this->uaRepository->getIsDecreasedSession();
        $this->isDecreasedIp = 
        $this->uaRepository->getIsDecreasedIp();

        $this->isNoAnomalySession = 
        $this->uaRepository->getIsNoAnomalySession();
        $this->isNoAnomalyIp = 
        $this->uaRepository->getIsNoAnomalyIp();

        $this->recaptchaSolved = 
        $this->requestContent->getRecaptchaSolved();

        $this->isSuspiciousAccess = 
        $this->getIsSuspiciousAccess();

        //  参照するプロパティがすべて初期化された後に、
        //  evaluate() を呼び出してリスク評価を行い、
        // その結果をプロパティに保持します。
        $this->riskEvaluationResult = $this->evaluate();

        $this->currentScoreSession =
        $this->riskEvaluationResult->getScoreForSession();
        $this->currentScoreIp      =
        $this->riskEvaluationResult->getScoreForIp();

        // currentScore（今回evaluate()後）と 
        // previousScore（DB取得値）を比較して
        // スコアが下がったかどうかを判定する
        $this->resultIsDecreasedSession =
            $this->isScoreDecreased(
                $this->currentScoreSession,
                $this->previousScoreSession
            );
        $this->resultIsDecreasedIp =
            $this->isScoreDecreased(
                $this->currentScoreIp,
                $this->previousScoreIp
            );
    }
    /**
     * アクセス回数が閾値を超えているかどうかを判定するメソッド
     * @param int $accessCount アクセス回数
     * @param int $threshold 閾値
     * @return int 閾値を超えている場合は1、そうでない場合は0を返す
     */
    public function isOverThreshold(int $accessCount, int $threshold): int {
        if ($accessCount >= $threshold) {
            return 1;
        } else {
            return 0
            ;
        }
    }

    private function getIsSuspiciousAccess(): int {
        if ($this->isNoUa === 1) {
            return 1;
        } 
        if ($this->isUaMismatch === 1) {
            return 1;
        }
        if ($this->isOverThresholdSession === 1) {
            return 1;
        }
        if ($this->isOverThresholdIp === 1) {
            return 1;
        }
        return 0;
    }

    public function getIsSuspiciousAccessFlag(): int {
        return $this->isSuspiciousAccess;
    }
    //  リスク評価が重複して行われることを防ぐために、
    //  evaluate() を呼び出すのはコンストラクタ内で一度だけにし、
    //  その結果をプロパティに保持するようにしています。
    //  テストなどで、evaluate() の結果を取得したい場合は、
    //  getRiskEvaluationResult() メソッドを
    //  通じてアクセスするようにします。
    private function evaluate(): RiskEvaluationResult {
        // スコアを取得
        $currentScoreSession  = $this->previousScoreSession;
        $currentScoreIp       = $this->previousScoreIp;

        //  疑わしいアクセスかのフラグ
        $isSuspiciousAccess = $this->isSuspiciousAccess;

        if ($this->isNoUa===1) {
            $currentScoreSession += 1;
            $currentScoreIp      += 1;
        }
        //  UA がない場合は、
        //  user agent を ''
        //  そして
        //  simple ua を '' としているが、
        //  '' を ua として他の ua と比較することは、
        //  適切ではない。例えば、
        //  ページ遷移前の UA が '' であり
        //  ページ遷移後の UA が '' である場合は、
        //  両方の UA が欠落しているだけで、
        //  UAが一致しているとは言えない。
        //  したがって、
        //  UA 不一致のフラグは、
        //  UA がない場合は使用できない。
        //  そのため、
        //  isNoUaのフラグも確認して、
        //  UA 不一致かつ isNoUa が立っていない
        //  場合にスコアを加算するロジックにする
        if ($this->isUaMismatch===1 and $this->isNoUa !== 1) {
            $currentScoreSession += 2;
            $currentScoreIp      += 2;
        }

        if ($this->isOverThresholdSession === 1) {
            $currentScoreSession += 3;
        }

        if ($this->isOverThresholdIp === 1) {
            $currentScoreIp += 3;
        }

        // if ($this->isDecreasedSession !== 1) {
        //     if ($this->isNoAnomalySession === 1) {
        //         $currentScoreSession -= 1;
        //         //  ゼロ以下にならないようにする
        //         if ($currentScoreSession < 0) {
        //             $currentScoreSession = 0;
        //         }
        //     }
        //     if ($this->recaptchaSolved === 1) {
        //         $currentScoreSession -= 4;
        //         //  ゼロ以下にならないようにする
        //         if ($currentScoreSession < 0) {
        //             $currentScoreSession = 0;
        //         }
        //     }    
        // }

        // 上記のロジックが重複するので、
        //  decreaseScore メソッドにまとめる

        // const DECREASE_SCORE_SESSION= 4;
        // const DECREASE_SCORE_IP = 1;
        // と定義してあります。
        
        
        $currentScoreSession = $this->decreaseScore(
            $currentScoreSession,
            $isSuspiciousAccess,
            $this->isDecreasedSession,
            $this->isNoAnomalySession,
            $this->recaptchaSolved,
            self::DECREASE_SCORE_SESSION
        );
        

        // if ($this->isDecreasedIp !== 1) {
        //     if ($this->isNoAnomalyIp === 1) {
        //         $currentScoreIp -= 1;
        //         //  ゼロ以下にならないようにする
        //         if ($currentScoreIp < 0) {
        //             $currentScoreIp = 0;
        //         }
        //     }
        //     if ($this->recaptchaSolved === 1) {
        //         $currentScoreIp -= 4;
        //         //  ゼロ以下にならないようにする
        //         if ($currentScoreIp < 0) {
        //             $currentScoreIp = 0;
        //         }
        //     }    
        // }

        $currentScoreIp = $this->decreaseScore(
            $currentScoreIp,
            $isSuspiciousAccess,
            $this->isDecreasedIp,
            $this->isNoAnomalyIp,
            $this->recaptchaSolved,
            self::DECREASE_SCORE_IP

        );

        return new RiskEvaluationResult($currentScoreSession, $currentScoreIp);
    }

    public function getIsOverThresholdSession(): int {
        return $this->isOverThresholdSession;
    }

    public function getIsOverThresholdIp(): int {
        return $this->isOverThresholdIp;
        }
    //  getter of $riskEvaluationResult
    public function getRiskEvaluationResult(): RiskEvaluationResult {
        return $this->riskEvaluationResult; 
    }

    // getter for resultIsDecreasedSession and resultIsDecreasedIp
    public function getResultIsDecreasedSession(): int {
        return $this->resultIsDecreasedSession;
    }

    public function getResultIsDecreasedIp(): int {
        return $this->resultIsDecreasedIp;
    }



    /**
     * スコアを減算する関数
     * 
     * $decreasedが1の場合は、
     * 30分以内に減算されたことを意味し、
     * さらに減算は行わない。
     * 
     * $isNoAnomalyが1の場合は、
     * 10分以内に異常がないことを意味し、
     * スコアを減算する。(-1)
     * 
     * $isNoAnomalyが0の場合は、
     * 条件分岐
     * - $isNoAnomalyが0で、$recaptchaSolvedが1の場合は、
     * 疑わしいと判断されたが、
     * reCAPTCHAを解いてアクセスして来る場合で、
     * 信用することにして、スコアを減算する。(-$decreaseScore)
     * - $isNoAnomalyが0で、
     * $recaptchaSolvedが0の場合は、
     * 過去10分以内に疑わしいと判断されたことがあり、
     * 直近で reCAPTCHAを解いていない場合であり、
     * スコアを減算しない。
     * 
     * @param  int $score 減算するスコア
     * @param  int $isSuspiciousAccess 疑わしいアクセスかどうかのフラグ
     * @param  int $decreased 30分以内に減算されたかどうかのフラグ
     * @param  int $isNoAnomaly 10分以内に異常がない場合のフラグ
     * @param  int $recaptchaSolved reCAPTCHAを解いたかどうかのフラグ
     * @return int $score減算後のスコア（0未満にならないようにする）
     * 
     */
    private function decreaseScore(
        int $score, 
        int $isSuspiciousAccess,
        int $decreased, 
        int $isNoAnomaly,
        int $recaptchaSolved,
        int $decreaseScore  //  subject_type に応じて減算するスコアを指定する
        ): int {

        //  疑わしいアクセスの場合は、スコアを減算しない
        if ($isSuspiciousAccess === 1) {
            return $score;
        }

        // 30分以内に減算された場合は
        // さらに減算はしない
        if ($decreased === 1) {
            return $score;
        }

        if ($isNoAnomaly === 1) {
            // 10分以内に異常がない場合はスコアを1減算
            $score -= 1;
            //  ゼロ以下にならないようにする
            $score = max($score, 0);

            return $score;

            //  10分以内に異常がない場合で
            //  reCAPTCHAを解いてアクセスして来る場合は
            //  は、想定されないが、
            //  -1減算し、return するロジックにする

            }
            
        if ($recaptchaSolved === 1) {
                // 異常があった場合でreCAPTCHAを
                // 解いた場合はスコアを4減算

                /*$isNoAnomaly === 1 と判定されれば、
                このifブロックに入ることはない。*/

                // 異常があって、10分以上経過して
                // reCAPTCHAを解いてアクセス
                // して来る場合は通常ありえない。
                // つまり、異常なし 
                // かつ 
                // reCAPTCHAを解いてアクセス
                // して来る場合は想定されないアクセスであると考えられる。
                // したがって、
                // この 
                //  if ブロックで
                // 異常があって、
                // reCAPTCHAを解いてアクセスして来る場合は
                // スコアを$decreaseScore減算するというロジックにする
                //  ただし、$decreaseScoreは
                //  subject_type に応じて減算するスコアを指定する
                //  このクラスの冒頭で定義してある
                //  const DECREASE_SCORE_SESSION= 4;
                //  const DECREASE_SCORE_IP = 1;
                //  を使用する。
            $score -= $decreaseScore;
                //  ゼロ以下にならないようにする
            $score = max($score, 0);

            return $score;

            }
            // 異常があって、
            // 直近で reCAPTCHAを解いていない場合は
            // スコアを減算しない
            return $score;
    }


    private function isScoreDecreased(
        int $currentScore,
        int $previousScore
        ): int {
        if ($currentScore < $previousScore) {
            return 1;
        } // END IF
        return 0;
    } // END FUNCTION

    // getter for isNoAnomalySession and isNoAnomalyIp
    public function getIsNoAnomalySession(): int {
        return $this->isNoAnomalySession;
    } // END FUNCTION getIsNoAnomalySession()

    public function getIsNoAnomalyIp(): int {
        return $this->isNoAnomalyIp;
    } // END FUNCTION getIsNoAnomalyIp()

} // END CLASS