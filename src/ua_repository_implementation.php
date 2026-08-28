<?php


class UaRepositoryImplementation implements UaRepository {
    
    //  プロパティ

    // serverからの基本情報
    private string $sessionId;
    private string $ipAddress;

    // PDO のインスタンスを保持するプロパティ
private PDO $pdo;

    //  databaseからの情報
    private int $scoreSession;
    private int $scoreIp;

    private int $isNoAnomalySession;
    private int $isNoAnomalyIp;

    private int $isDecreasedSession;
    private int $isDecreasedIp;

    // メソッド間でデータを共有するためのプロパティ
    private array $accessCountArray;
    private int $accessCountSession;
    private int $accessCountIp;

    private array $decreasedCountArray;

    private array $anomalyCountArray;
    private array $isNoAnomalyFlagArray;

    //  コンストラクタで 
    // $SessionId と $IpAddress を初期化する
    //  PDO のインスタンスを受け取る
    public function __construct(PDO $pdo, string $sessionId, string $ipAddress) {
        $this->pdo = $pdo;

        $this->sessionId = $sessionId;
        $this->ipAddress = $ipAddress;

        $this->scoreSession = $this->fetchScore($this->pdo, (string)$this->sessionId, 'session');
        $this->scoreIp      = $this->fetchScore($this->pdo, (string)$this->ipAddress, 'ip');

        $this->accessCountArray   = $this->fetchAccessCountArray($this->pdo, (string)$this->sessionId, (string)$this->ipAddress);
        $this->accessCountSession = $this->extractAccessCountSession($this->accessCountArray);
        $this->accessCountIp      = $this->extractAccessCountIp($this->accessCountArray);

        $this->decreasedCountArray = $this->countIsDecreasedLast30MinutesForTwoSubjects(
            $this->pdo,
            (string)$this->sessionId, 'session',
            (string)$this->ipAddress, 'ip'
        );
        $this->isDecreasedSession = $this->extractSessionDecreasedFlag($this->decreasedCountArray) ;
        $this->isDecreasedIp      = $this->extractIpDecreasedFlag($this->decreasedCountArray);


        $this->anomalyCountArray =
        $this->countAnomalyLast10MinFor2(
            $this->pdo,
            $this->sessionId, 
            $this->ipAddress
        );

        $this->isNoAnomalyFlagArray = $this->convertCountsToNoAnomalyFlags($this->anomalyCountArray);
        $this->isNoAnomalySession = $this->isNoAnomalyFlagArray['session'];
        $this->isNoAnomalyIp      = $this->isNoAnomalyFlagArray['ip'];

    }


    //  追跡対象に対するスコアを返す getter
    public function getScoreSession(): int{
        return $this->scoreSession;
    }
    public function getScoreIp(): int{
        return $this->scoreIp;
    }

    //  data base から score を取得する
    //  テストのために、$pdo を引数に取る private メソッドを定義する
    private function fetchScore(PDO $pdo, string $subjectKey, string $subjectType): int{
        // ここでデータベースからスコアを取得するロジックを実装
        // 例: SQLクエリを実行して、$subjectKey と $subjectType に基づいてスコアを取得する
        // 取得したスコアを返す

//         CREATE TABLE ua_scores (
//   subject_type ENUM('session', 'ip') NOT NULL,
//   subject_key  VARCHAR(128) NOT NULL,
//   score        INT UNSIGNED NOT NULL DEFAULT 0,
//   updated_at   DATETIME NOT NULL
//     DEFAULT CURRENT_TIMESTAMP
//     ON UPDATE CURRENT_TIMESTAMP,
//   PRIMARY KEY (subject_type, subject_key)
// ) ENGINE=InnoDB
//   DEFAULT CHARSET=utf8mb4
//   COLLATE=utf8mb4_unicode_ci;

    //  $pdo を使用して、データベースからスコアを取得する
        $stmt = $pdo->prepare("SELECT score FROM ua_scores WHERE subject_type = :subjectType AND subject_key = :subjectKey");
        $stmt->execute(['subjectType' => $subjectType, 'subjectKey' => $subjectKey]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        // fetch(PDO::FETCH_ASSOC) は、
        // 実行済みのSQLクエリの結果セットから 
        // 1行だけ 取得し、
        // カラム名をキーとする連想配列 として返します。
        // データがない場合は false を返します。
    if ($result !== false) {
            return (int)$result['score'];
            } else {
                return 0; // スコアが見つからない場合は 0 を返す
            }

    }
    

    // アクセス回数を返す getter
    public function getAccessCountSession(): int{
        return $this->accessCountSession;
    }
    public function getAccessCountIp(): int{
        return $this->accessCountIp;
    }

    //  data base からアクセス回数を配列で取得する
    //  実装で記述
    private function fetchAccessCountArray(PDO $pdo, string $sessionId, string $ipAddress): array {
        // ここでデータベースからアクセス回数を取得するロジックを実装
        // 例: SQLクエリを実行して、$sessionId と $ipAddress に基づいてアクセス回数を取得する
        // 取得したアクセス回数の配列を返す

//         CREATE TABLE user_agent_logs (
//   id             INT AUTO_INCREMENT PRIMARY KEY,
//   session_id     VARCHAR(128) NOT NULL,
//   ip_address     VARCHAR(64)  NOT NULL,
//   simple_ua      VARCHAR(128) NOT NULL,
//   is_ua_mismatch TINYINT(1)   NOT NULL,
//   access_time    DATETIME     NOT NULL,
//   INDEX idx_sess_ip_time (session_id, ip_address, access_time)
// ) 

        //  データベースのuser_agent_logsの session_id カラムが $sessionId
        //  であるレコードを取得する。
        //  ip_address カラムが $ipAddress に一致するレコードを取得する。

        //  以上の二つのレコードのレコード数をカウントして、
        //  配列で返す。
        /**
 * 直近1分間のアクセス数を取得
 *
 * 戻り値の例:
 * [
 *   'session_id_access_count' => 5,
 *   'ip_address_access_count' => 2,
 * ]
 */
// function ua_get_access_count_last_minute(PDO $pdo, string $session_id, string $ip_address): array {
//     $sql = "SELECT 
//                 COUNT(CASE WHEN session_id = :sid THEN 1 END) as session_id_access_count,
//                 COUNT(CASE WHEN ip_address = :ip THEN 1 END) as ip_address_access_count
//             FROM user_agent_logs 
//             WHERE access_time >= (NOW() - INTERVAL 1 MINUTE)";

//     $stmt = $pdo->prepare($sql);

//     // パラメータのバインドと実行
//     $stmt->execute([
//         ':sid' => $session_id,
//         ':ip'  => $ip_address,
//     ]);

//     // 結果を連想配列として取得
//     $result = $stmt->fetch(PDO::FETCH_ASSOC);
//     $access_count_last_minute = $result;
//     return $access_count_last_minute;
// }
                        // session_idがプレースホルダーである :sid と等しい場合に 1 をカウントし、そうでない場合は NULL を返す
                        // ip_addressがプレースホルダーである :ip と等しい場合に
                        // 1 をカウントし、そうでない場合は NULL を返す
                        // これにより、session_id と ip_address の両方のアクセス数
                        // count は、null出ない値の数をカウントすることになります。
        $sql = "SELECT 
                COUNT(CASE WHEN session_id = :sid THEN 1 END) as session_id_access_count,
                COUNT(CASE WHEN ip_address = :ip THEN 1 END) as ip_address_access_count
                FROM user_agent_logs 
                WHERE access_time >= (NOW() - INTERVAL 1 MINUTE)";

        $stmt = $pdo->prepare($sql);

        // パラメータのバインドと実行
        // プレイスホルダーに値をバインドしてクエリを実行する
        $stmt->execute([
            ':sid' => $sessionId,
            ':ip'  => $ipAddress,
        ]);

        // 結果を連想配列として取得
        // 値は文字列で返されるため、(int) キャストして整数に変換する
        $resultArray = $stmt->fetch(PDO::FETCH_ASSOC);

        $accessCountLastMinuteArray['session_id_access_count'] = (int)$resultArray['session_id_access_count'];
        $accessCountLastMinuteArray['ip_address_access_count'] = (int)$resultArray['ip_address_access_count'];
    

        return $accessCountLastMinuteArray;


        }




    //  配列からアクセス回数を取得する
    //  戻り値の例:
    //  [
    //   'session_id_access_count' => 5,
    //     'ip_address_access_count' => 2,
    //   ]

    //  実装で記述
    // public function extractAccessCountSession(array $accessCountArray): int;
    // public function extractAccessCountIp(array $accessCountArray): int;
    private function extractAccessCountSession(array $accessCountArray): int {
        $accessCountSession = $accessCountArray['session_id_access_count'] ?? 0;
        return $accessCountSession;
    }

    private function extractAccessCountIp(array $accessCountArray): int {
        $accessCountIp = $accessCountArray['ip_address_access_count'] ?? 0;
        return $accessCountIp;        
    }

    // スコアが減少したかどうかを返す getter（1/0想定）
    // public function getIsDecreasedSession(): int;
    // public function getIsDecreasedIp(): int;


//     CREATE TABLE ua_score_history (
//   id                INT AUTO_INCREMENT PRIMARY KEY,
//   subject_type      ENUM('session', 'ip') NOT NULL,
//   subject_key       VARCHAR(128) NOT NULL,
//   is_no_ua          TINYINT(1) NOT NULL DEFAULT 0,
//   is_ua_mismatch    TINYINT(1) NOT NULL DEFAULT 0,
//   is_over_threshold_session TINYINT(1) NOT NULL DEFAULT 0,
//   is_over_threshold_ip TINYINT(1) NOT NULL DEFAULT 0,
//   is_no_anomaly     TINYINT(1) NOT NULL DEFAULT 0,
//   recaptcha_solved  TINYINT(1) NOT NULL DEFAULT 0,
//   is_decreased      TINYINT(1) NOT NULL DEFAULT 0,
//   access_time       DATETIME NOT NULL,
//   INDEX idx_subject_time (subject_type, subject_key, access_time)
// ) ENGINE=InnoDB
//   DEFAULT CHARSET=utf8mb4
//   COLLATE=utf8mb4_unicode_ci;


    /**
     * データベースの
     * ua_score_history テーブルで
     * subject_key カラム が $subject_keyで、
     * subject_type カラム が $subject_type であるレコードのうち、
     * is_decreased カラムの値が 1 で
     * access_time が直近30分以内のレコードの数をカウントする。
     * 
     */

    //  SQL 文の説明
    //  SELECT COUNT(*) as decreased_count
    //  SELECT COUNT(*) は条件に一致するレコードの数をカウントします。
    //  as decreased_count は、
    //  カウントされた数に decreased_count 
    //  というエイリアスを付けることを意味します。
    //  PHP 側で $result['decreased_count'] としてアクセスできるようになる。
    //  呼び出し元では、この値が 0 より大きければ直近30分間にスコア減少があったと判断する用途で使われます。

    //  session ベースと ip ベースの値を一度で取得したいため、
    //  refactor します。
    //  従って以下のメソッドをコメントアウトします。
    // private function countIsDecreasedLast30Minutes(PDO $pdo, string $subjectKey, string $subjectType): int {
    //     $sql = "SELECT COUNT(*) as decreased_count
    //             FROM ua_score_history
    //             WHERE subject_key = :subjectKey
    //               AND subject_type = :subjectType
    //               AND is_decreased = 1
    //               AND access_time >= (NOW() - INTERVAL 30 MINUTE)";

    //     $stmt = $pdo->prepare($sql);
    //     $stmt->execute([
    //         ':subjectKey' => $subjectKey,
    //         ':subjectType' => $subjectType,
    //     ]);

    //     $result = $stmt->fetch(PDO::FETCH_ASSOC);
    //     return (int)$result['decreased_count'];
    // }


    /**
 * database のtable ua_score_historyから、
 * subject_key カラム が $sessionIdかつ
 * subject_type カラム が $session 
 * であるレコードの数をカウントする。
 * 連想配列の 'session_decreased_count' キーにカウントされた数を格納する。
 * そして
 * subject_key カラム が $ipAddressかつ
 * subject_type カラム が $ip であるレコードの数をカウントする。
 * 連想配列の 'ip_decreased_count' キーにカウントされた数を格納する。
 * そして、連想配列を返す。
 * fetch される値は、
 * デフォルトでは文字列であるため、
 * (int) キャストして整数に変換する。
 */

    private function countIsDecreasedLast30MinutesForTwoSubjects(PDO $pdo, string $sessionId, string $session, string $ipAddress, string $ip): array {
        $sql = "SELECT 
                    COUNT(CASE WHEN subject_key = :sessionId AND subject_type = :session_id AND is_decreased = 1 THEN 1 END) as session_decreased_count,
                    COUNT(CASE WHEN subject_key = :ipAddress AND subject_type = :ip_address AND is_decreased = 1 THEN 1 END) as ip_decreased_count
                    
                FROM ua_score_history WHERE access_time >= (NOW() - INTERVAL 30 MINUTE)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':sessionId' => $sessionId,
            ':session_id' => $session,
            ':ipAddress' => $ipAddress,
            ':ip_address' => $ip,
        ]);

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return [
            // COUNT の値は文字列で返されるため、(int) キャストして整数に変換する
            'session_decreased_count' => (int)$result['session_decreased_count'],
            'ip_decreased_count' => (int)$result['ip_decreased_count'],
        ];
    }

    //  countIsDecreasedLast30MinutesForTwoSubjects() の結果から、
    //  session ベースと ip ベースの値を取得して、
    //  ゼロより大きければ 1 を返す。
    private function extractSessionDecreasedFlag(array $decreasedCountArray): int {
        $decreasedCountSession = $decreasedCountArray['session_decreased_count'] ?? 0;
        return $decreasedCountSession > 0 ? 1 : 0;
    }

    private function extractIpDecreasedFlag(array $decreasedCountArray): int {
        $decreasedCountIp = $decreasedCountArray['ip_decreased_count'] ?? 0;
        return $decreasedCountIp > 0 ? 1 : 0;
    }

    

    
    public function getIsDecreasedSession(): int{
        return $this->isDecreasedSession;
    }
    public function getIsDecreasedIp(): int{
        return $this->isDecreasedIp;
    }
    
    // data base でスコアが減少したかどうかを確認する
    //  実装で記述
    // public function checkIsDecreasedLast30Minutes(string $subjectType, string $subjectKey): int;


    //  DB へのアクセス回数よりも、
    //  インデックスの適切な利用のほうが
    //  パフォーマンスに寄与する可能性が高いため、
    //  以下のメソッドは、リファクタリング
     private function countAnomalyLast10MinFor2(PDO $pdo, string $sessionId, string $ipAddress): array {
        // ここでデータベースから異常イベントの数を取得するロジックを実装
        // 例: SQLクエリを実行して、$sessionId と $ipAddress に基づいて異常イベントの数を取得する
        // 取得した異常イベントの数を配列で返す

        //  データベースのua_anomaly_eventsの session_id カラムが $sessionId
        //  であるレコードの数をカウントする。

        //  データベースのua_anomaly_eventsの ip_address カラムが $ipAddress
        //  であるレコードの数をカウントする。


//         CREATE TABLE ua_anomaly_events (
// id INT AUTO_INCREMENT PRIMARY KEY,
// session_id VARCHAR(128) NOT NULL,
// ip_address VARCHAR(45) NOT NULL,
// is_no_ua TINYINT(1) NOT NULL DEFAULT 0,
// is_ua_mismatch TINYINT(1) NOT NULL DEFAULT 0,
// is_over_threshold_session TINYINT(1) NOT NULL DEFAULT 0,
// is_over_threshold_ip TINYINT(1) NOT NULL DEFAULT 0,
// access_time DATETIME NOT NULL,
// INDEX idx_session_time (session_id, access_time),
// INDEX idx_ip_time (ip_address, access_time),
// INDEX idx_time (access_time)
// ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    $sql = "SELECT 'session' as type, COUNT(*) as anomaly_count
            FROM ua_anomaly_events 
            WHERE session_id = :sessionId AND access_time >= (NOW() - INTERVAL 10 MINUTE)
            UNION ALL
            SELECT 'ip' as type, COUNT(*) as anomaly_count
            FROM ua_anomaly_events 
            WHERE ip_address = :ipAddress AND access_time >= (NOW() - INTERVAL 10 MINUTE);
            ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':sessionId' => $sessionId,
            ':ipAddress' => $ipAddress,
        ]);

        $resultArray = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // このクエリを実行して、
        // fetchAll すると、以下のような結果が得られます。
        // $anomalyCountArrayString = [
        //     ['type' => 'session', 'anomaly_count' => '5'],
        //     ['type' => 'ip', 'anomaly_count' => '3']
        // ]; 

        $anomalyCountArray = ['session' => 0, 'ip' => 0]; // デフォルト値を設定
        foreach ($resultArray as $row) {
            if ($row['type'] === 'session') {
                $anomalyCountArray['session'] = (int)$row['anomaly_count'];
            } elseif ($row['type'] === 'ip') {
                $anomalyCountArray['ip'] = (int)$row['anomaly_count'];
            }
        }

        return $anomalyCountArray;

    }


    //     $sql = "SELECT 
    //                 COUNT(CASE WHEN session_id = :sessionId THEN 1 END) as session_anomaly_count,
    //                 COUNT(CASE WHEN ip_address = :ipAddress THEN 1 END) as ip_anomaly_count
                    
    //             FROM ua_anomaly_events WHERE access_time >= (NOW() - INTERVAL 10 MINUTE)";

    //     $stmt = $pdo->prepare($sql);
    //     $stmt->execute([
    //         ':sessionId' => $sessionId,
    //         ':ipAddress' => $ipAddress,
    //     ]);

    //     $result = $stmt->fetch(PDO::FETCH_ASSOC);

    //     return [
    //         // COUNT の値は文字列で返されるため、(int) キャストして整数に変換する
    //         'session_anomaly_count' => (int)$result['session_anomaly_count'],
    //         'ip_anomaly_count' => (int)$result['ip_anomaly_count'],
    //     ];

    // }


    private function convertCountsToNoAnomalyFlags(array $anomalyCountArray): array {
        return [
            'session' => $anomalyCountArray['session'] === 0 ? 1 : 0,
            'ip' => $anomalyCountArray['ip'] === 0 ? 1 : 0,
        ];
    }
    // 追跡対象に異常がない場合は 1 を返す getter
    public function getIsNoAnomalySession(): int{
        return $this->isNoAnomalySession;
    }
    public function getIsNoAnomalyIp(): int{
        return $this->isNoAnomalyIp;
    }

    // data base で異常フラグがあるレコードの数を配列で取得する
    //  実装で記述
    // public function checkIsNoAnomalyLast10Minutes(string $sessionId, string $ipAddress): int;
    // 配列の要素の数から、
    // セッションID/IPアドレスに異常がないかどうかを取得する
    //  実装で記述
    // public function plunkIsNoAnomalySession(array $isNoAnomalyArray): int;
    // public function plunkIsNoAnomalyIp(array $isNoAnomalyArray): int;


    // UA に関するアクセスログを保存する
    //  実装で記述
    // public function recordUserAgentLogs(
    //     string $sessionId,
    //     string $ipAddress,
    //     string $simpleUa,
    //     int    $isUaMismatch
    // ): void;

    // 異常イベントを保存する
    //  実装で記述
    // public function recordAnomalyEvents(
    //     string $sessionId,
    //     string $ipAddress,
    //     int    $isNoUa,
    //     int    $isUaMismatch,
    //     int    $isOverThresholdSession,
    //     int    $isOverThresholdIp
    // ): void;

    // UA スコアを保存する（session / ip 共通）
    // subjectKey と subjectType が
    // 同じレコードがあれば更新、なければ新規作成する
    //  実装で記述
    // public function recordUaScores(
    //     string $subjectKey,
    //     string $subjectType,
    //     int    $score
    // ): void;

    // UA スコア履歴を保存する（session / ip 共通）
    //  実装で記述
    // public function recordUaScoreHistory(
    //     string $subjectKey,
    //     string $subjectType,
    //     int    $isNoUa,
    //     int    $isUaMismatch,
    //     int    $isOverThresholdSession,
    //     int    $isOverThresholdIp,
    //     int    $isNoAnomaly,  //last10minutes
    //     int    $recaptchaSolved,
    //     int    $isDecreased  //last30minutes
    // ): void;



}


?>

<?php
/**
 * database のtable ua_score_historyから、
 * subject_key カラム が $sessionIdかつ
 * subject_type カラム が $session 
 * であるレコードの数をカウントする。
 * 連想配列の 'session_decreased_count' キーにカウントされた数を格納する。
 * そして
 * subject_key カラム が $ipAddressかつ
 * subject_type カラム が $ip であるレコードの数をカウントする。
 * 連想配列の 'ip_decreased_count' キーにカウントされた数を格納する。
 * そして、連想配列を返す。
 * fetch される値は、
 * デフォルトでは文字列であるため、
 * (int) キャストして整数に変換する。
 */

    // function countIsDecreasedLast30MinutesForTwoSubjects(PDO $pdo, string $sessionId, string $session, string $ipAddress, string $ip): array {
    //     $sql = "SELECT 
    //                 COUNT(CASE WHEN subject_key = :sessionId AND subject_type = :session_id AND is_decreased = 1 AND access_time >= (NOW() - INTERVAL 30 MINUTE) THEN 1 END) as session_decreased_count,
    //                 COUNT(CASE WHEN subject_key = :ipAddress AND subject_type = :ip_address AND is_decreased = 1 AND access_time >= (NOW() - INTERVAL 30 MINUTE) THEN 1 END) as ip_decreased_count
    //             FROM ua_score_history";

    //     $stmt = $pdo->prepare($sql);
    //     $stmt->execute([
    //         ':sessionId' => $sessionId,
    //         ':session_id' => $session,
    //         ':ipAddress' => $ipAddress,
    //         ':ip_address' => $ip,
    //     ]);

    //     $result = $stmt->fetch(PDO::FETCH_ASSOC);
    //     return [
    //         // COUNT の値は文字列で返されるため、(int) キャストして整数に変換する
    //         'session_decreased_count' => (int)$result['session_decreased_count'],
    //         'ip_decreased_count' => (int)$result['ip_decreased_count'],
    //     ];
    // }


