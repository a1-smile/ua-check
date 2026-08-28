<?php
/**
 * student アプリの
 * セキュリティの部分における
 * ユーザーエージェント チェックを
 * 行うモジュールの概要は以下の通りです。
 * 
 * request_content_implementation.php
 * の
 * class RequestContentImplementation implements RequestContent
 * でサーバーからのリクエストに関する情報を取得します。
 * 
 * ua_repository_implementation.php
 * の
 * class UaRepositoryImplementation implements UaRepository
 * でDBから過去のアクセス情報取得します。
 * 
 * user_agent_risk_evaluator.php
 * の
 * class UserAgentRiskEvaluator 
 * でユーザーエージェントのリスク評価を行います。
 * 
 * write-ua.php
 * でリスク評価の結果や、アクセス情報をDBに保存します。
 * 
 * class WriteUaを定義します。
 */

class WriteUa{
  // error_code
  const   DB_WRITE_ERROR = 1;
  
  private PDO $pdo;
  private RequestContent $requestContent;
  private UaRepository $uaRepository; 

  private UserAgentRiskEvaluator $userAgentRiskEvaluator;

  private RiskEvaluationResult $riskEvaluationResult;

  private string $sessionId;
  private string $ipAddress;
  private string $simpleUa;
  private int    $isUaMismatch;

  private int $isNoUa;
  private int $isOverThresholdSession;
  private int $isOverThresholdIp; 

  private int $scoreSession;
  private int $scoreIp;

  private int $recaptchaSolved;
  private int $isDecreasedSession;
  private int $isDecreasedIp;

  private int $isNoAnomalySession;
  private int $isNoAnomalyIp;


  public function __construct(
    PDO $pdo,
    RequestContent $request_content,
    UaRepository $ua_repository,
    UserAgentRiskEvaluator $user_agent_risk_evaluator
    ) {
        $this->pdo = $pdo;
        $this->requestContent = $request_content;
        $this->uaRepository   = $ua_repository;

        $this->userAgentRiskEvaluator =
          $user_agent_risk_evaluator;

        $this->sessionId    = $this->requestContent->getSessionId();
        $this->ipAddress    = $this->requestContent->getIpAddress();
        $this->simpleUa     = $this->requestContent->getCurrentSimpleUa();
        $this->isUaMismatch = $this->requestContent->getIsUaMismatch();

        $this->isNoUa = $this->requestContent->getIsNoUa();

        $this->isOverThresholdSession =
          $this->userAgentRiskEvaluator->getIsOverThresholdSession();
        $this->isOverThresholdIp =
          $this->userAgentRiskEvaluator->getIsOverThresholdIp();

        $this->riskEvaluationResult =
          $this->userAgentRiskEvaluator->getRiskEvaluationResult  ();

        $this->scoreSession =
          $this->riskEvaluationResult->getScoreForSession();
        $this->scoreIp      =
          $this->riskEvaluationResult->getScoreForIp();

        $this->recaptchaSolved =
          $this->requestContent->getRecaptchaSolved();

        $this->isDecreasedSession =
          $this->userAgentRiskEvaluator->getResultIsDecreasedSession();
        $this->isDecreasedIp =
          $this->userAgentRiskEvaluator->getResultIsDecreasedIp();

        $this->isNoAnomalySession =
          $this->userAgentRiskEvaluator->getIsNoAnomalySession();
        $this->isNoAnomalyIp =
          $this->userAgentRiskEvaluator->getIsNoAnomalyIp();
    } // END CONSTRUCT
    /**
     * user_agent_logs テーブルにデータを記録する処理
     *
     * @throws DbWriteException PDO失敗時
     * @throws DbRowCountException ０行INSERT時
     */
    public function writeUserAgentLog(): void {
    $pdo = $this->pdo;
    $sessionId = $this->sessionId;
    $ipAddress = $this->ipAddress;
    $simpleUa = $this->simpleUa;
    $isUaMismatch = $this->isUaMismatch;
    
      // user_agent_logs テーブルにデータを記録する処理
      $sql = "INSERT INTO user_agent_logs (
                session_id,
                ip_address,
                simple_ua,
                is_ua_mismatch, 
                access_time
                )
              VALUES (
                :session_id,
                :ip_address,
                :simple_ua,
                :is_ua_mismatch,
                NOW())";

      //  $stmt を try-catch の外で参照
      //  すると、未定義の可能性があると、
      //  PHPStan に指摘されることがあります。
      //  このような静的解析ツールの
      //  ルールに従うために、
      //  事前に null で初期化しておきます。
      $stmt = null;

      try{
          $stmt = $pdo->prepare($sql);
          
          //  パラメーターの型を指定してバインドする
          $stmt->bindParam(':session_id', $sessionId, PDO::PARAM_STR);
          $stmt->bindParam(':ip_address', $ipAddress, PDO::PARAM_STR);
          $stmt->bindParam(':simple_ua', $simpleUa, PDO::PARAM_STR);
          $stmt->bindParam(':is_ua_mismatch', $isUaMismatch, PDO::PARAM_INT);
          $stmt->execute();
      }catch(PDOException $e){
          throw new DbWriteException('writeUserAgentLog failed: ' . $e->getMessage(),
          self::DB_WRITE_ERROR, //  code は自分で定義する。通常定数化する。マジックナンバーは避ける。 
          $e //  再スローする例外の前の例外のインスタンス。
          ); 
      } // END TRY CATCH

      //  $stmt が DBエラーなどで
      //  null のままここまで到達する
      //  ことはありません。
      //  PDO の設定によって、
      //  エラーが発生した場合に例外がスローされるためです。
      //  なので、
      //  if ($stmt === null) 
      //  のようなチェックはなしで、
      //  $stmt->rowCount() を呼び出すことができます。
      
      //  INSERTが正しく行われたか確認するために、影響を受けた行数をチェックする
      if ($stmt->rowCount() !== 1) {
          throw new DbRowCountException('writeUserAgentLog: INSERT affected 0 rows.');
      } // END IF
            

    } // END FUNCTION writeUserAgentLog()


  /**
  * ua_anomaly_events テーブルにデータを記録する処理
  *  CREATE TABLE ua_anomaly_events (
  * id INT AUTO_INCREMENT PRIMARY KEY,
  * session_id VARCHAR(128) NOT NULL,
  * ip_address VARCHAR(45) NOT NULL,
  * is_no_ua TINYINT(1) NOT NULL DEFAULT 0,
  * is_ua_mismatch TINYINT(1) NOT NULL DEFAULT 0,
  * is_over_threshold_session TINYINT(1) NOT NULL DEFAULT 0,
  * is_over_threshold_ip TINYINT(1) NOT NULL DEFAULT 0,
  * access_time DATETIME NOT NULL,
  * INDEX idx_session_time (session_id, access_time),
  * INDEX idx_ip_time (ip_address, access_time),
  * INDEX idx_time (access_time)
  *) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  *
  *もし、
  * $isNoUa が 0 かつ
  * $isUaMismatch が 0 かつ
  * $isOverThresholdSession が 0 かつ
  * $isOverThresholdIp が 0
  *のときは、UAに異常がないと判断して、
  *ua_anomaly_events テーブルには記録しない。
  *何もせずに returnする。
  *
  *@throws DbWriteException PDO失敗時
  * PDOExceptionをキャッチして、
  * DbWriteExceptionにラップしてスローする。
  * 書き込みに失敗した場合にスローされる例外です。
  *
  *@throws DbRowCountException ０行INSERT時
  *期待した行数が影響を受けなかった場合にスローされる例外
  *この二つの例外を組み合わせることによって、
  *DBでのエラーは発生しなかったが、
  *ロジックエラーなどで正しく
  *データが記録されなかった場合も検知できるようにする。
  * 要するに、DBに書きこみがあった場合は、
  * 必ず1行が影響を受けるということを確認しています。
  * 0行だった場合は、何らかの問題があったと判断して例外をスローする。
  * no anomaly で早期リターンの場合と、
  * エラーでレコードが挿入されない場合を
  * 区別することができます。
  */
  public function writeUaAnomalyEvents(): void {
    $pdo = $this->pdo;
    $sessionId = $this->sessionId;
    $ipAddress = $this->ipAddress;
    $isNoUa = $this->isNoUa;
    $isUaMismatch = $this->isUaMismatch;
    $isOverThresholdSession = $this->isOverThresholdSession;
    $isOverThresholdIp = $this->isOverThresholdIp;
    // UAに異常がない場合は何もせずに return
    if (
        $isNoUa === 0 
            && 
        $isUaMismatch === 0 
            && 
        $isOverThresholdSession === 0 
            && 
        $isOverThresholdIp === 0
        ) {
        return;
    }

    // ua_anomaly_events テーブルにデータを記録する処理
    $sql = "INSERT INTO ua_anomaly_events (
              session_id,
              ip_address,
              is_no_ua,
              is_ua_mismatch,
              is_over_threshold_session,
              is_over_threshold_ip,
              access_time
            ) VALUES (
              :session_id,
              :ip_address,
              :is_no_ua,
              :is_ua_mismatch,
              :is_over_threshold_session,
              :is_over_threshold_ip,
              NOW())";

    $stmt = null; // 事前に null で初期化しておく
    //  try-catch ブロックの外で $stmt を参照するため、
    //  事前に null で初期化しておきます。

    try{
      $stmt = $pdo->prepare($sql);
      // パラメーターの型を指定してバインドする
      $stmt->bindParam(':session_id', $sessionId, PDO::PARAM_STR);
      $stmt->bindParam(':ip_address', $ipAddress, PDO::PARAM_STR);
      $stmt->bindParam(':is_no_ua', $isNoUa, PDO::PARAM_INT);
      $stmt->bindParam(':is_ua_mismatch', $isUaMismatch, PDO::PARAM_INT);
      $stmt->bindParam(':is_over_threshold_session', $isOverThresholdSession, PDO::PARAM_INT);
      $stmt->bindParam(':is_over_threshold_ip', $isOverThresholdIp, PDO::PARAM_INT);
      $stmt->execute();
    }catch(PDOException $e){
        throw new DbWriteException('writeUaAnomalyEvents failed: ' . $e->getMessage(),
        self::DB_WRITE_ERROR, //  code は自分で定義する。通常定数化する。マジックナンバーは避ける。 
        $e //  再スローする例外の前の例外のインスタンス。
        ); 
    } // END TRY CATCH

    //  $stmt が DBエラーなどで  null のままここまで到達することはありません。
    //  PDO の設定によって、エラーが発生した場合に例外がスローされるためです。
    //  なので、if ($stmt === null) のようなチェックはなしで
    //  $stmt->rowCount() を呼び出すことができます。
    //  INSERTが正しく行われたか確認するために、影響を受けた行数をチェックする
    if ($stmt->rowCount() !== 1) {
        throw new DbRowCountException('writeUaAnomalyEvents: INSERT affected 0 rows.');
    } // END IF

  } // END FUNCTION writeUaAnomalyEvents()


  /**
    * CREATE TABLE ua_scores (
    * subject_type ENUM('session', 'ip') NOT NULL,
    * subject_key  VARCHAR(128) NOT NULL,
    * score        INT UNSIGNED NOT NULL DEFAULT 0,
    * updated_at   DATETIME NOT NULL
    * DEFAULT CURRENT_TIMESTAMP
    * ON UPDATE CURRENT_TIMESTAMP,
    * PRIMARY KEY (subject_type, subject_key)
    * ) ENGINE=InnoDB
    * DEFAULT CHARSET=utf8mb4
    *  COLLATE=utf8mb4_unicode_ci;
    * に
    * セッションベースのスコアとIPベースのスコアを記録する。
    * もし、すでに同じ session_id 
    * もしくは ip_address 
    * のレコードが存在する場合は、
    * スコアを更新する。
    * 存在しない場合は、新規にレコードを挿入する。
    *

   */

  public function writeUaScores(): void{
    $pdo = $this->pdo;
    $sessionId = $this->sessionId;
    $ipAddress = $this->ipAddress;
    $scoreSession = $this->scoreSession;
    $scoreIp = $this->scoreIp;
    // セッションベースのスコアを記録

    // $sqlSession = "INSERT INTO ua_scores (subject_type, subject_key, score, updated_at)
    //                VALUES ('session', :session_id, :score_session, NOW())
    //                ON DUPLICATE KEY UPDATE score = :score_session, updated_at = NOW()";

    //  同一パラメーターを INSERT と UPDATE の両方でしようすると、
    //  PDO::prepare() でエラーになることがあります。
    //  そのため、コメントアウトして、
    // INSERT と UPDATE で
    // 別々のscoreに対するパラメーター名
    // (プレイスホルダー) を使うようにします。
    // （:score_insert と :score_update ）を使うようにします。
    //  以下のような記述に変更します。

    $sqlSession = "
        INSERT INTO ua_scores (
            subject_type,
            subject_key,
            score,
            updated_at
      )
VALUES (
    'session',
    :session_id,
    :score_insert,
    NOW()
)
ON DUPLICATE KEY UPDATE
    score = :score_update,
    updated_at = NOW()
";

    try{
      $stmtSession = $pdo->prepare($sqlSession);
      $stmtSession->bindParam(':session_id', $sessionId, PDO::PARAM_STR);
      $stmtSession->bindParam(':score_insert', $scoreSession, PDO::PARAM_INT);
      $stmtSession->bindParam(':score_update', $scoreSession, PDO::PARAM_INT);
      $stmtSession->execute();
      //  INSERTが正しく行われたか確認することを、
      //  rowCount() でチェックすることは難しいです。
      //  以下に理由をコメントで説明します。
      /* 
      writeUaScores() の rowCount の注意点（別件）
      ON DUPLICATE KEY UPDATE を使った場合、MySQL では：

      INSERT 成功 → rowCount() === 1
      UPDATE 発生 → rowCount() === 2
      UPDATE 発生 だが値は変わらない → rowCount() === 0
      SQL失敗 で、例外がスローされなかった、
       つまり、PDOException はスローされなかったが、
       何らかの理由でレコードが挿入も更新もされなかった場合 → rowCount() === 0
      そのため rowCount() !== 1 のチェックは 
      UPDATE 時と、
      UPDATE 発生 だが値は変わらない
      場合に 
       DbRowCountException
      を誤スローします。
      なので、
      upsert の場合は、rowCount() で、
      業務上期待する処理を行ったかどうかを判断するのは難しいです。
      
      また、select を用いて確認する方法もありますが、これも完璧ではありません。
       なぜなら、select して確認した時点と、
       実際に insert/update が行われる時点の間に、
       別のリクエストが同じ session_id/ip_address に対して
       insert/update を行う可能性があるからです。
       つまり、レースコンディションの問題が発生します。
       そのため、厳密に正確に処理を確認するのは難しいです。

       また、UPSERT のたびに、select して確認するのは
       パフォーマンスの観点からも望ましくありません。

       そして、DB操作 と DB検証 の二つの責務を
        一つの関数で行うと、コードが複雑になり、保守性が低下します。

        以上の理由から、ON DUPLICATE KEY UPDATE を使った場合の
        rowCount() のチェックは、
        行わず、PDOException がスローされなかった場合は、
        正常に処理が行われたとみなすのが現実的です。
      */
      
    }catch(PDOException $e){
        throw new DbWriteException('writeUaScores (session) failed: ' . $e->getMessage(),
                                  self::DB_WRITE_ERROR,
                                  $e
                                  );
    } // END TRY CATCH

    // IPベースのスコアを記録
    // $sqlIp = "INSERT INTO ua_scores (subject_type, subject_key, score, updated_at)
    //           VALUES ('ip', :ip_address, :score_ip, NOW())
    //           ON DUPLICATE KEY UPDATE score = :score_ip, updated_at = NOW()";

    $sqlIp = "
INSERT INTO ua_scores (
    subject_type,
    subject_key,
    score,
    updated_at
)
VALUES (
    'ip',
    :ip_address,
    :score_ip,
    NOW()
)
ON DUPLICATE KEY UPDATE
    score = :score_update_ip,
    updated_at = NOW()
";
    try{
      $stmtIp = $pdo->prepare($sqlIp);
      $stmtIp->bindParam(':ip_address', $ipAddress, PDO::PARAM_STR);
      $stmtIp->bindParam(':score_ip', $scoreIp, PDO::PARAM_INT);
      $stmtIp->bindParam(':score_update_ip', $scoreIp, PDO::PARAM_INT);
      $stmtIp->execute();
    }catch(PDOException $e){
        throw new DbWriteException('writeUaScores (ip) failed: ' . $e->getMessage(),
                                  self::DB_WRITE_ERROR,
                                  $e
                                  );
    } // END TRY CATCH
  } // END FUNCTION writeUaScores()


//   CREATE TABLE ua_score_history (
//   id                INT AUTO_INCREMENT PRIMARY KEY,
//   subject_type      ENUM('session', 'ip') NOT NULL,
//   subject_key       VARCHAR(128) NOT NULL,
//   is_no_ua          TINYINT(1) NOT NULL DEFAULT 0,
//   is_ua_mismatch    TINYINT(1) NOT NULL DEFAULT 0,
//   is_over_threshold TINYINT(1) NOT NULL DEFAULT 0,
//   is_no_anomaly     TINYINT(1) NOT NULL DEFAULT 0,
//   recaptcha_solved  TINYINT(1) NOT NULL DEFAULT 0,
//   is_decreased      TINYINT(1) NOT NULL DEFAULT 0,
//   access_time       DATETIME NOT NULL,
//   INDEX idx_subject_time (subject_type, subject_key, access_time)
// ) ENGINE=InnoDB
//   DEFAULT CHARSET=utf8mb4
//   COLLATE=utf8mb4_unicode_ci;
/**
 * ua_score_history テーブルには、
 * アクセスがあるたびに、
 * session_id と
 * ip_address 両方について、
 * アクセス情報を記録します、
 * 
 * session base で考えていきます。
 * 
 * subject_type : 'session'
 * subject_key : $sessionId
 * is_no_ua : $isNoUa
 * is_ua_mismatch : $isUaMismatch
 * is_over_threshold : $isOverThresholdSession
 * is_no_anomaly : $isNoAnomalySession
 * recaptcha_solved : $recaptchaSolved
 * is_decreased : $isDecreasedSession
 * access_time : NOW()
 * 
 * ip base で考えていきます。
 * 
 * subject_type : 'ip'
 * subject_key : $ipAddress
 * is_no_ua : $isNoUa
 * is_ua_mismatch : $isUaMismatch
 * is_over_threshold : $isOverThresholdIp
 * is_no_anomaly : $isNoAnomalyIp
 * recaptcha_solved : $recaptchaSolved
 * is_decreased : $isDecreasedIp
 * access_time : NOW()
 */
//  ua_score_history table に
//  session base と ip base の両方の
//  情報を記録するメリットは、
//  table 数が増えない。
//  全履歴を一元管理できる。

//  デメリットは、
//  同じカラムを二つの目的で使うため、
//  書き込む処理が複雑になる。
//  読むときも、session base か ip base かを判別する必要がある。
//  削除処理も、session base か ip base かで分ける場合は、複雑になる。


  public function writeUaScoreHistory(): void {
    $pdo = $this->pdo;
    $sessionId = $this->sessionId;
    $ipAddress = $this->ipAddress;
    $isNoUa = $this->isNoUa;
    $isUaMismatch = $this->isUaMismatch;
    $isOverThresholdSession = $this->isOverThresholdSession;
    $isNoAnomalySession = $this->isNoAnomalySession;
    $isOverThresholdIp = $this->isOverThresholdIp;
    $isNoAnomalyIp = $this->isNoAnomalyIp;
    $recaptchaSolved = $this->recaptchaSolved;
    $isDecreasedSession = $this->isDecreasedSession;
    $isDecreasedIp = $this->isDecreasedIp;
    // session base のスコア履歴を記録
    $sqlSession = "INSERT INTO ua_score_history (
                    subject_type, subject_key, is_no_ua, is_ua_mismatch, 
                    is_over_threshold, is_no_anomaly, recaptcha_solved, 
                    is_decreased, access_time)
                   VALUES (
                    'session', :session_id, :is_no_ua, :is_ua_mismatch, 
                    :is_over_threshold_session, :is_no_anomaly_session, 
                    :recaptcha_solved, :is_decreased_session, NOW())";
    try{
        $stmtSession = $pdo->prepare($sqlSession);
        $stmtSession->bindParam(':session_id', $sessionId, PDO::PARAM_STR);
        $stmtSession->bindParam(':is_no_ua', $isNoUa, PDO::PARAM_INT);
        $stmtSession->bindParam(':is_ua_mismatch', $isUaMismatch, PDO::PARAM_INT);
        $stmtSession->bindParam(':is_over_threshold_session', $isOverThresholdSession, PDO::PARAM_INT);
        $stmtSession->bindParam(':is_no_anomaly_session', $isNoAnomalySession, PDO::PARAM_INT);
        $stmtSession->bindParam(':recaptcha_solved', $recaptchaSolved, PDO::PARAM_INT);
        $stmtSession->bindParam(':is_decreased_session', $isDecreasedSession, PDO::PARAM_INT);
        $stmtSession->execute();
        //  INSERTが正しく行われたか確認するために、影響を受けた行数をチェックする
        if ($stmtSession->rowCount() !== 1) {
            throw new DbRowCountException('writeUaScoreHistory (session): INSERT affected 0 rows.');
        } // END IF
    }catch(PDOException $e){
        throw new DbWriteException('writeUaScoreHistory (session) failed: ' . $e->getMessage(),
                                  self::DB_WRITE_ERROR,
                                  $e
                                  ); 
    } // END TRY CATCH
    // ip base のスコア履歴を記録
    $sqlIp = "INSERT INTO ua_score_history (
                subject_type, subject_key, is_no_ua, is_ua_mismatch, 
                is_over_threshold, is_no_anomaly, recaptcha_solved, 
                is_decreased, access_time)
              VALUES (
                'ip', :ip_address, :is_no_ua, :is_ua_mismatch, 
                :is_over_threshold_ip, :is_no_anomaly_ip,
                :recaptcha_solved, :is_decreased_ip, NOW())";
    // パラメーターの型を指定してバインドする
    try{
        $stmtIp = $pdo->prepare($sqlIp);
        $stmtIp->bindParam(':ip_address', $ipAddress, PDO::PARAM_STR);
        $stmtIp->bindParam(':is_no_ua', $isNoUa, PDO::PARAM_INT);
        $stmtIp->bindParam(':is_ua_mismatch', $isUaMismatch, PDO::PARAM_INT);
        $stmtIp->bindParam(':is_over_threshold_ip', $isOverThresholdIp, PDO::PARAM_INT);
        $stmtIp->bindParam(':is_no_anomaly_ip', $isNoAnomalyIp, PDO::PARAM_INT);
        $stmtIp->bindParam(':recaptcha_solved', $recaptchaSolved, PDO::PARAM_INT);
        $stmtIp->bindParam(':is_decreased_ip', $isDecreasedIp, PDO::PARAM_INT);
        $stmtIp->execute();                                                             
        //  INSERTが正しく行われたか確認するために、影響を受けた行数をチェックする
        if ($stmtIp->rowCount() !== 1) {
            throw new DbRowCountException('writeUaScoreHistory (ip): INSERT affected 0 rows.');
        } // END IF
    }catch(PDOException $e){
        throw new DbWriteException('writeUaScoreHistory (ip) failed: ' . $e->getMessage(),
                                  self::DB_WRITE_ERROR,
                                  $e
                                  ); 
    } // END TRY CATCH
  } // END FUNCTION writeUaScoreHistory()

} // END CLASS
