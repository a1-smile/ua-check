<?php
/*
ua-check/tests/test-write-ua-scores.php
では、
student/write-ua.php
に定義されている
class WriteUaのwriteUaScores() メソッドをテストします。
*/

/* test case decision table
主要なテストケースのディシジョンテーブル
status
--------------------------------------------------
score_session | insert | insert | update | update 
score_ip      | insert | update | insert | update 
--------------------------------------------------
action
--------------------------------------------------
record count  | +2     | +1      | +1    | +0     
*/

/* テストケース
(pass)session insert / ip insert
(pass)session update / ip update (both score change)
(pass)session insert / ip update (score ip change)
(pass)session update (score session change) / ip insert

(pass)session insert / ip update but score ip same value
(pass)session update / ip insert but score session same value
(pass)session update / ip update but both score same value
(pass)session update (score change) / ip update (score same)	混在パターン
(pass)session update (score same) / ip update (score change)	混在パターン
(pass)subject_key 128文字の境界値テスト
(pass)subject_key 129文字の境界値テスト
(pass)access count session59, 60, 61 の境界値テスト
(pass)access count ip 599, 600, 601 の境界値テスト

(pass) //加算ロジック is_no_ua === 1 単独テスト（score += 1）
(pass) //加算ロジック is_ua_mismatch === 1 単独テスト（score += 2）
(pass) //加算ロジック is_no_ua===1 かつ is_ua_mismatch===1: is_ua_mismatch を無視し score += 1 のみ
(pass) //複合条件 is_ua_mismatch === 1
and  access_count is_over_threshold === 1 の場合のテスト

    # decreaseScore()の分岐テスト
    (pass)1. isSuspiciousAccess === 1      → return (no decrease)  ✅
    (pass)2. decreased_session === 1       → return (no decrease)  ✅
    (pass)2. decreased_ip === 1            → return (no decrease)  ✅
    (pass)3. isNoAnomaly_session === 1     → score -= 1, return    ✅
    (pass)3. isNoAnomaly_ip === 1          → score -= 1, return    ✅
    (pass)4. recaptchaSolved === 1         → score -= 4/1, return  ✅
    (pass)4. recaptcha session floor clamp → score < 4 → max(0)   ✅
    (pass)4. recaptcha ip floor clamp      → score_ip=0, 0-1→0   ✅
    (pass)5. else                          → return (no decrease)  ✅

*/

/* risk score を
計算する仕様を説明します。
テスト用の expected score はこの仕様の
ハードコードによって計算します。
また、
*これにより、risk score を計算するロジック
をテストコード内で明示的に表現できるようにもなります。 


    //  $is_no_ua === 1（uaなし）の場合は、risk score に1点加算します。
    
    //  $is_no_ua === 0（uaあり）の場合は、
    //  遷移前と遷移後で、ua を比較する。
    //  ua がない場合は、比較できないので、$is_ua_mismatch の値は無視します。
    //  遷移前と遷移後で、ua が異なる場合は、risk score に2点加算します。
    
    //  過去1分のアクセス数が閾値を超えている場合は、
    //  risk score に3点加算します。
    
    //  ここまでで、加算が完了。

    //  ここから、減算のロジックです。

    //  疑わしいアクセスの場合は、
    // 減算のロジックを適用せず、
    // 加算後のスコアで確定します。
    // 疑わしいという判定は
    //  ua なし、
    //  ua 不一致、
    //  過去1分のアクセス数が閾値を超えている、
    //  のいずれかに該当する場合です。

    //  過去30分にスコアが減点されたアクセスがある場合は、
    //  減算のロジックを適用せず、
    //  加算後のスコアで確定します。

    //  過去10分に異常がなかった場合は、
    //  減算のロジックを適用し、1点減点します。

    //  過去10分に異常がなかった場合は、次の項目の
    //  recaptcha_solved の判定を行わず、
    // ここで確定します。
    // 異常がなく、かつ recaptcha を通過、
    // というケースは、想定されないためです。

    //  recaptcha を通過した場合は、
    //  減算のロジックを適用し、
    //  subject_type に応じた減算値を減点します。
    //    session ベースでは、4点減点します。
    //    ip ベースでは、1点減点します。

    //  減算の条件に該当しない場合は、
    //  加算後のスコアを計算結果とします。
*/

//  過去1分のアクセス数が閾値を超えているかどうかを判定する関数を定義します。
function checkOverThreshold(int $access_count_last1min, int $threshold): int
{
    return ($access_count_last1min >= $threshold) ? 1 : 0;
}  // END function checkOverThreshold()

//  table ua_scores を TRUNCATE する関数を定義します。
function truncateUaScoresTable(PDO $pdo): void
{
    try {
        $pdo->exec("TRUNCATE TABLE ua_scores");
        echo "Table ua_scores truncated successfully.<br><br>";
    } catch (Exception $e) {
        echo "Error truncating table ua_scores: " . $e->getMessage() . "<br><br>";
        exit(1);
    }  // END try-catch
}  // END function truncateUaScoresTable()

/**
 * runTestWriteUaScores() 関数を定義します。
 * writeUaScores()を呼び出し、
 * SELECTで取得した値と期待値を照合します。
 * @param string $caseLabel
 * テストケースのラベルを指定します。何をテストするか。
 * 
 * @param array $contents
 * モックで、サーバーからの情報を提供するための配列です。
 * [
 *   'session_id' => 'abc123',
 *   'ip_address' => '192.168.0.1',
 *   'simple_ua' => 'Chrome/91',
 *   'is_no_ua' => 1,
 *   'is_ua_mismatch' => 0,
 *   'recaptcha_solved' => 0,
 * ]
 * @param array $uaData
 * モックで、DBの情報を提供するための配列です。
 * [
 *  'score_session' => 0,
 *  'score_ip' => 0,
 *  'access_count_session' => 0,
 *  'access_count_ip' => 0,
 *  'is_decreased_session' => 0,
 *  'is_decreased_ip' => 0,
 *  'is_no_anomaly_session' => 0,
 *  'is_no_anomaly_ip' => 0,
 * ]
 * @param int $scoreSessionExpected
 * session ベースの score の期待値を指定します。
 * @param int $scoreIpExpected
 * IP ベースの score の期待値を指定します。
 * @param PDO $pdo
 * PDO インスタンスを指定します。
 * 
 * @param bool $clearDb
 * true の場合、テスト開始前に table ua_scores を TRUNCATE します。
 */

function runTestWriteUaScores(
    string $caseLabel,
    array  $contents,
    array  $uaData,
    int    $scoreSessionExpected,
    int    $scoreIpExpected,
    PDO    $pdo,
    bool   $clearDb = true
): void {
    echo "<b>{$caseLabel}</b><br>";

    if ($clearDb) {
        // table ua_scores をクリア
        truncateUaScoresTable($pdo);
    }  //END IF

    $mock_request_content = new MockRequestContent1($contents);
    $mock_ua_repository  = new MockUaRepository($uaData);
    $risk_evaluator = new UserAgentRiskEvaluator($mock_request_content, $mock_ua_repository);
    $write_ua       = new WriteUa($pdo, $mock_request_content, $mock_ua_repository, $risk_evaluator);
    try {
        $write_ua->writeUaScores();
    } catch (DbWriteException $e) {
        die("  Error writing anomaly events: " . $e->getMessage() . "<br><br>");
    } catch (Exception $e) {
        die("  Unexpected error: " . $e->getMessage() . "<br><br>");
    }  // END try-catch

    // SELECTで session に紐づいた record を取得する。そして期待値と照合する
    $session_id = $mock_request_content->getSessionId();
    try {
        $stmt = $pdo->prepare("SELECT * FROM ua_scores WHERE subject_key = :session_id");
        $stmt->bindParam(':session_id', $session_id, PDO::PARAM_STR);
        $stmt->execute();
        $row  = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        die("  Error querying table: " . $e->getMessage() . "<br><br>");
    }
    if ($row === false) {
        $totalFail++;
        die("  FAIL: No log entry found in ua_scores.<br><br>");
    }

    $ok = check('subject_key_session_mock', $row['subject_key'], $session_id);
    $ok = check('subject_key_session_contents', $row['subject_key'], $contents['session_id']) && $ok;
    $ok = check('scoreSession', $row['score'], $scoreSessionExpected) && $ok;
    $ok = check('type', $row['subject_type'], 'session') && $ok;

    //  access_time が現在から5秒以内であることを確認します。
    //  まず、DBに記録された access_time を DateTime オブジェクトに変換します。
    $access_time = new DateTime($row['updated_at']);
    //  現在の時間を DateTime オブジェクトで取得します。
    $now  = new DateTime();
    //  Unix タイムスタンプの差を計算します。
    //  int なので、単純に引き算できます。
    $diff = $now->getTimestamp() - $access_time->getTimestamp();
    $ok = check('access_time_session', $diff >= 0 && $diff < ACCEPTABLE_TIME_DIFF_SEC, true) && $ok;

    //  session のチェックが失敗した場合は、ip のチェックをスキップします。
    //  実行しても test の信頼性が低いためです。
    if (!$ok) {
        die("  session checks failed. skipping ip checks.<br><br>");
    }

    // SELECTで ip address に紐づいた record を取得する。そして期待値と照合する
    $ip_address = $mock_request_content->getIpAddress();
    try {
        $stmt = $pdo->prepare("SELECT * FROM ua_scores WHERE subject_key = :ip_address");
        $stmt->bindParam(':ip_address', $ip_address, PDO::PARAM_STR);
        $stmt->execute();
        $row  = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        die("  Error querying table: " . $e->getMessage() . "<br><br>");
    }
    if ($row === false) {
        die("  FAIL: No log entry found in ua_scores.<br><br>");
    }

    $ok = check('subject_key_ip_mock', $row['subject_key'], $ip_address);
    $ok = check('subject_key_ip_contents', $row['subject_key'], $contents['ip_address']) && $ok;
    $ok = check('scoreIp', $row['score'], $scoreIpExpected) && $ok;
    $ok = check('type', $row['subject_type'], 'ip') && $ok;

    //  access_time が現在から5秒以内であることを確認します。
    //  まず、DBに記録された access_time を DateTime オブジェクトに変換します。
    $access_time = new DateTime($row['updated_at']);
    //  現在の時間を DateTime オブジェクトで取得します。
    $now  = new DateTime();
    //  Unix タイムスタンプの差を計算します。
    //  int なので、単純に引き算できます。
    $diff = $now->getTimestamp() - $access_time->getTimestamp();
    $ok = check('access_time_ip', $diff >= 0 && $diff < ACCEPTABLE_TIME_DIFF_SEC, true) && $ok;

    if ($ok) {
        echo "  All checks passed.<br><br>";
    } else {
        //  test 失敗のため stop します。
        die("Ip test failed. Stopping further tests.<br><br>");
    }
    echo "<br>";
}  // END function runTestWriteUaScores()

//  table ua_scores のレコード件数を取得する関数を定義します。
function getRecordCount(PDO $pdo): int
{
    try {
        $stmt = $pdo->query("SELECT COUNT(*) FROM ua_scores");
        return (int)$stmt->fetchColumn();
    } catch (Exception $e) {
        echo "  Error counting records: " . $e->getMessage() . "<br><br>";
        return -1; // エラーの場合は -1 を返す
    }  // END try-catch
}  // END function getRecordCount()

//  record count が期待値と一致するかどうかをチェックする関数を定義します。
function checkRecordCount(
    string $caseLabel,
    PDO $pdo,
    int $expectedCount
): void {
    echo "<b>{$caseLabel}</b><br>";

    global $totalPass, $totalFail;

    $actualCount = getRecordCount($pdo);
    if ($actualCount === -1) {
        $totalFail++;
        die("  FAIL: Could not retrieve record count.<br><br>");
    }

    if ($actualCount === $expectedCount) {
        $totalPass++;
        echo "  PASS: Record count is as expected. Count: {$actualCount}<br><br>";
    } else {
        $totalFail++;
        die("  FAIL: Record count is not as expected. Expected: {$expectedCount}, Actual: {$actualCount}<br><br>");
    }
} // END function checkRecordCount()


/**
 * runTestCaseError() 関数を定義します。
 * writeUaScores() を呼び出し、例外が発生することを期待します。
 * 例外が発生しない場合は、テスト失敗とします。
 * @param string $caseLabel
 * テストケースのラベルを指定します。何をテストするか。
 * 
 * @param array $contents
 * モックで、サーバーからの情報を提供するための配列です。
 * [
 *   'session_id' => 'abc123',
 *   'ip_address' => '127.0.0.1',
 * ]
 * @param array $uaData
 * モックで、DBの情報を提供するための配列です。
 * [
 *  'score_session' => 0,
 * 'score_ip' => 0,
 * 'access_count_session' => 0,
 * 'access_count_ip' => 0,
 * 'is_decreased_session' => 0,
 * 'is_decreased_ip' => 0,
 * 'is_no_anomaly_session' => 0,
 * 'is_no_anomaly_ip' => 0,
 * ]
 * @param PDO $pdo
 * PDO インスタンスを指定します。
 * 
 * 戻り値は void です。例外が発生した場合は、PASS として処理を終了します。
 * 例外が発生しなかった場合は、FAIL として処理を終了します。
 */
function runTestCaseError(
    string $caseLabel,
    array $contents,
    array $uaData,
    PDO $pdo
): void {
    echo "<b>{$caseLabel}</b><br>";

    global $totalPass, $totalFail;

    // table ua_scores をクリア
    try {
        $pdo->exec("TRUNCATE TABLE ua_scores");
    } catch (Exception $e) {
        die("  Error truncating table: " . $e->getMessage() . "<br><br>");
    }

    $mock = new MockRequestContent1($contents);

    $mock_ua_repository  = new MockUaRepository($uaData);
    $risk_evaluator = new UserAgentRiskEvaluator($mock, $mock_ua_repository);
    $write_ua       = new WriteUa($pdo, $mock, $mock_ua_repository, $risk_evaluator);

    try {
        $write_ua->writeUaScores();
        $totalFail++;
        die("  FAIL: 例外が発生しませんでした。デバッグが必要です。<br><br>");
    } catch (RuntimeException $e) {
        $totalPass++;
        echo "  PASS: 例外が発生しました: " . $e->getMessage() . "<br><br>";
        return;
    } // END try-catch
} // END function runTestCaseError()


//  以上で、関数定義は終了です。

//  test に必要な設定をします。

//  タイムゾーンを明示的に設定します。
//  sql と php で時間がずれるのを防ぐためです。
date_default_timezone_set('Asia/Tokyo');


//  定数を定義します。

//  DBへのアクセス時刻と現在の時刻の差の上限を定数として定義します。
//  許容される時間の差を秒単位で定義します。
//  環境や状況によっては、
//  アクセス時間と現在の時間に
//  数秒の差が生じることがあるので、
//  10~30sec くらいの値を設定してください。
const ACCEPTABLE_TIME_DIFF_SEC = 10;

//  subject_type が session の場合、recaptcha 通過時に減算する値
//  hardcode で、計算するためコメントアウトします。
//const DECREASE_SCORE_FOR_SESSION = 4; // subject_type が session の場合、recaptcha 通過時に減算する値

//  subject_type が ip の場合、recaptcha 通過時に減算する値
//  hardcode で、計算するためコメントアウトします。
//const DECREASE_SCORE_FOR_IP = 1; // subject_type が ip の場合、recaptcha 通過時に減算する値    

const CLEAR_DB = true; // テスト開始前にDBをクリアするかどうか。true にすると、テスト開始前に table ua_scores を TRUNCATE します。
const NOT_CLEAR_DB = false; // テスト開始前にDBをクリアしない場合。テストケースによっては、前のテストケースのデータが残っていることを前提とするものもあるため、こちらの定数も定義しておきます。

//to do:const  MAX_SUBJECT_KEY_LENGTH = 128; // subject_key の最大長を定義します。128文字を超える場合は、例外が発生することを想定しています。
const JUST_THRESHOLD_SESSION = 60; // access_count_session の閾値を定義します。カウントする時間は1分間です。
const JUST_THRESHOLD_IP = 600; // access_count_ip の閾値を定義します。カウントする時間は1分間です。

//  DBManager クラスを使用するために、require_once します。
require_once __DIR__ . '/../common/dbmanager.php';
//  DBManager を new します。
$dbManager = new DBManager();
//  データベースに接続します。
try {
    $dbManager->connect();
    echo "Database connection successful.<br><br>";
} catch (Exception $e) {
    echo "Database connection failed: " . $e->getMessage() . "<br><br>";
    exit(1);
}
//  PDO インスタンスを取得します。
$pdo = $dbManager->get_db();

//  RequestContent インターフェイスを、require_once します。
require_once __DIR__ . '/../interface_request_content.php';

//  RequestContentImplementation クラスを、require_once します。
//  mock_request_content.php 内で、simple ua を求めるときに 
//  RequestContentImplementation の静的メソッドを使用するためです。
require_once __DIR__ . '/../request_content_implementation.php';

//  その他のテストに必要なファイルも require_once します。
require_once __DIR__ . '/../mock_request_content.php';
require_once __DIR__ . '/../interface_ua_repository.php';
require_once __DIR__ . '/../mock_ua_repository.php';
require_once __DIR__ . '/../risk_evaluation_result.php';
require_once __DIR__ . '/../user_agent_risk_evaluator.php';
require_once __DIR__ . '/../write-ua.php';
require_once __DIR__ . '/../exceptions.php';
require_once __DIR__ . '/function-check.php';

// -------------------------------------------------------
// session insert / ip insert
// $is_no_ua === 1
//  
// -------------------------------------------------------

//  runTestWriteUaScores() の引数を定義します。
$caseLabel = 'Case<br>session insert / ip insert, $is_no_ua === 1';

$contents = [
    'session_id'      => 'abc123',
    'ip_address'      => '192.168.0.1',
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 1,  // score 1 加算
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => 0, // 閾値 60
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0, // 'is_no_ua' => 1 と設定してあり、異常があるアクセスなので、こちらの値はスコアに影響しません。
    'is_no_anomaly_ip' => 0       // 異常があるアクセスなので、こちらの値はスコアに影響しません。
];

$is_over_threshold_session =
    checkOverThreshold(
        $uaData['access_count_session'],
        JUST_THRESHOLD_SESSION
    );
$is_over_threshold_ip =
    checkOverThreshold(
        $uaData['access_count_ip'],
        JUST_THRESHOLD_IP
    );

$scoreSessionExpected = 1;
/* 
table をTRUNCATE したので、
previous score 0

is no ua 1 => +1

ua がないので比較できない。
ゆえに、
不一致時の加算はなし。

過去1分のアクセス数が閾値を超えていないので、加算なし。

疑わしいアクセスなので、
減算のロジックは適用されず、
加算後のスコアが計算結果となります。
結果は、
score は 1 です。
    */

//  同様に、ip の score も計算しますと、
$scoreIpExpected = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

//  checkRecordCount() の引数を定義します。
$caseLabel = 'Check record count after session insert / ip insert';
$expectedCount = 2; // session と ip の2件が挿入されることを期待します。
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session update / ip update
// $is_no_ua === 1
//
// step 1: CLEAR_DB で insert を行い、score = 1 を書き込む。
// step 2: 同じ session_id / ip_address で NOT_CLEAR_DB にし update を行う。
//         mock の score_session/score_ip に step 1 で書き込んだ値 1 をセットする。
//         is_no_ua=1 → +1 加算 → score = 2 になることを確認する。
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する。
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session update / ip update, step 1: insert';

$contents = [
    'session_id'      => 'update_session_01',
    'ip_address'      => '10.0.0.1',
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 1,  // score +1
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,  // DB に記録なし → 0
    'score_ip'             => 0,  // DB に記録なし → 0
    'access_count_session' => 0,  // 閾値 60
    'access_count_ip'      => 0,  // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: update (NOT_CLEAR_DB, 同じ session_id / ip_address)
// $contents は step 1 と同じ変数をそのまま使用します（同一 session_id / ip_address）。
$caseLabel = 'Case<br>session update / ip update, step 2: update';

// mock の score_session / score_ip に
// step 1 で DB に書き込んだ値 1 をセットします。
// これにより「DB に score 1 が残っている状態から再アクセスした」状況を模倣します。
$uaData = [
    'score_session'        => 1,  // step 1 で DB に書かれたスコア
    'score_ip'             => 1,  // step 1 で DB に書かれたスコア
    'access_count_session' => 0,  // 閾値 60
    'access_count_ip'      => 0,  // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(1) + is_no_ua(+1) = 2
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 2;
$scoreIpExpected      = 2;

runTestWriteUaScores(
    $caseLabel,
    $contents,        // step 1 と同じ session_id / ip_address
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);    // クリアしない → UPDATE になることを確認

// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する。
$caseLabel = 'Record count = 2: UPDATE であり INSERT でないことを確認';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session insert / ip update
// $is_no_ua === 1
//
// このケースでは、
// 1回目のアクセスで session_id と ip_address の両方が新規に INSERT されます。
// 2回目のアクセスでは、
// session_id が異なる（→ session は INSERT）
// ip_address が同じ  （→ ip は UPDATE）
// 場合を確認します。
//
// step 1: CLEAR_DB で insert を行い、scoreSession=1 / scoreIp=1 を書き込む。
// step 2: 異なる session_id / 同じ ip_address で NOT_CLEAR_DB にして実行する。
//         session は新規 → INSERT（scoreSession: 0+1=1）
//         ip は既存  → UPDATE（scoreIp: 1+1=2）
//
// ip ベースの score を step 1（1）と step 2（2）で意図的に異なる値にしている理由：
// UPDATE 時に score が同じ値の場合と異なる値の場合で SQL の挙動が変わるため、
// UPDATE が確実に実行（値が変化）されることを確認するために、異なる値にしている。
//
// step 3: record count が 3 であることを確認する。
//         step 1 で session(01) + ip の 2 レコードが INSERT される。
//         step 2 で session(02) の 1 レコードが INSERT される。
//         ip は UPDATE されるため、レコードは増えない。
//         合計 3 レコードになることを確認する。
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session insert / ip update, step 1: insert (both)';

$contents = [
    'session_id'       => 'ip_update_session_01',  // step 1 のセッション ID
    'ip_address'       => '172.16.0.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 1,  // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,  // DB に記録なし → 0
    'score_ip'             => 0,  // DB に記録なし → 0
    'access_count_session' => 0,  // 閾値 60
    'access_count_ip'      => 0,  // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session INSERT / ip UPDATE (NOT_CLEAR_DB)
// session_id を変える（→ session は新規 INSERT）
// ip_address は step 1 と同じ（→ ip は UPDATE）
// score_ip に step 1 で DB に書かれた値 1 をセットすることで、
// 「DB に ip score 1 が残っている状態から別セッションがアクセスした」状況を模倣する。
$caseLabel = 'Case<br>session insert / ip update, step 2: session insert / ip update';

$contents = [
    'session_id'       => 'ip_update_session_02',  // step 1 と異なる session_id → session INSERT
    'ip_address'       => '172.16.0.1',             // step 1 と同じ ip_address → ip UPDATE
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 1,  // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,  // 新規セッション → DB に記録なし → 0
    'score_ip'             => 1,  // step 1 で DB に書かれた ip score
    'access_count_session' => 0,  // 過去1分間のアクセス数がありません。
    'access_count_ip'      => 1,  // step 1 で 1count されているという想定
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

//  score計算:
// session: previous(0) + is_no_ua(+1) = 1
// ip:      previous(1) + is_no_ua(+1) = 2
// → step 1 の ip score(1) と step 2 の ip score(2) が異なる値になることを確認する。
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 2;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → ip は UPDATE、session は INSERT になることを確認

// step 3: record count が 3 であることを確認する。
//   step 1: ip_update_session_01（session）+ 172.16.0.1（ip）= 2 レコード INSERT
//   step 2: ip_update_session_02（session）= 1 レコード INSERT、172.16.0.1（ip）= UPDATE（増えない）
//   合計 3 レコード
$caseLabel = 'Record count = 3: session(01) + ip + session(02) の合計を確認';
$expectedCount = 3;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session update (score change) / ip insert
// $is_no_ua === 1
//
// このケースでは、
// session base では過去にアクセスがあり（→ session は UPDATE）、
// ip base では新規アクセス（→ ip は INSERT）の場合を確認します。
// さらに、session の score が step1 → step2 で変化していることも確認します。
//
// step 1: CLEAR_DB で insert を行い、scoreSession=1 / scoreIp=1 を書き込む。
// step 2: 同じ session_id / 異なる ip_address で NOT_CLEAR_DB にして実行する。
//         session は既存 → UPDATE（scoreSession: 1+1=2、score が変化）
//         ip は新規     → INSERT（scoreIp: 0+1=1）
//
// session ベースの score を step 1（1）と step 2（2）で意図的に異なる値にしている理由：
// UPDATE 時に score が同じ値の場合と異なる値の場合で SQL の挙動が変わるため、
// UPDATE が確実に実行（値が変化）されることを確認するために、異なる値にしている。
//
// step 3: record count が 3 であることを確認する。
//         step 1 で su_change_session_01（session）+ 10.2.0.1（ip）= 2 レコード INSERT
//         step 2 で su_change_session_01（session）= UPDATE（増えない）、
//                  10.2.0.2（ip）= 1 レコード INSERT
//         合計 3 レコードになることを確認する。
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session update (score change) / ip insert, step 1: insert (both)';

$contents = [
    'session_id'       => 'su_change_session_01',  // step 1 のセッション ID
    'ip_address'       => '10.2.0.1',
    'simple_ua'        => '',  // is_no_ua が 1 なので、simple_ua は空になるという想定です。
    'is_no_ua'         => 1,  // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => '', //  ua がセットされていないばあいは、
    //  'user_agent' => '' となるロジックになっています。
];

$uaData = [
    'score_session'        => 0,  // DB に記録なし → 0
    'score_ip'             => 0,  // DB に記録なし → 0
    'access_count_session' => 0,  // 閾値 60
    'access_count_ip'      => 0,  // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 1,  // ここは、過去10分間に疑わしいアクセスがないというフラグです。
    'is_no_anomaly_ip'      => 1,  // 同上、ロジック上
    // 新規アクセスでは1となります。
    // 疑わしいアクセスの場合は
    // 減算処理は早期リターンされるため、
    // 減算は行われません。
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session UPDATE (score change) / ip INSERT (NOT_CLEAR_DB)
// session_id は step 1 と同じ（→ session は UPDATE）
// ip_address は step 1 と異なる（→ ip は新規 INSERT）
// score_session に step 1 で DB に書かれた値 1 をセットすることで、
// 「DB に session score 1 が残っている状態から同じセッションが再アクセスした」状況を模倣する。
// これにより session score が 1 → 2 に変化することを確認する。
$caseLabel = 'Case<br>session update (score change) / ip insert, step 2: session update / ip insert';

$contents = [
    'session_id'       => 'su_change_session_01',  // step 1 と同じ session_id → session UPDATE
    'ip_address'       => '10.2.0.2',              // step 1 と異なる ip_address → ip INSERT
    'simple_ua'        => '',  // is_no_ua が 1 なので、simple_ua は空になるという想定です。
    'is_no_ua'         => 1,  // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => '', //  ua がセットされていないばあいは、
    //  'user_agent' => '' となるロジックになっています。
];

$uaData = [
    'score_session'        => 1,  // step 1 で DB に書かれた session score → score が変化する根拠
    'score_ip'             => 0,  // 新規 IP → DB に記録なし → 0
    'access_count_session' => 1,  // step 1 で 1count されているという想定
    'access_count_ip'      => 0,  // 新規 IP なのでアクセス履歴なし
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // 過去10分間に疑わしいアクセスがあるというフラグです。
    'is_no_anomaly_ip'      => 1,  // 同上
    // 新規アクセスでは1となります。
    // 疑わしいアクセスの場合は
    // 減算処理は早期リターンされるため、
    // 減算は行われません。
];

// score 計算:
// session: previous(1) + is_no_ua(+1) = 2  ← step 1 の score(1) から変化していることを確認
// ip:      previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 2;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → session は UPDATE、ip は INSERT になることを確認

// step 3: record count が 3 であることを確認する。
//   step 1: su_change_session_01（session）+ 10.2.0.1（ip）= 2 レコード INSERT
//   step 2: su_change_session_01（session）= UPDATE（レコード増えない）、10.2.0.2（ip）= 1 レコード INSERT
//   合計 3 レコード
$caseLabel = 'Record count = 3: session + ip(10.2.0.1) + ip(10.2.0.2) の合計を確認';
$expectedCount = 3;
checkRecordCount($caseLabel, $pdo, $expectedCount);

/*---------------------------------------
test case
session insert / ip update
score ip same as previous

sql で、update する場合、
score が同じ値の場合と異なる値の場合で
挙動が変わるので、
update で値が同じ場合もテストします。

step1: insert (CLEAR_DB)
is_no_ua===1 → score +1 for each subject_type
ua===''
simple_ua === '' (is_no_ua===1 の場合、simple_ua は '' になる想定)

step2: session insert / ip update (NOT_CLEAR_DB)

    step1 と異なる session_id / 
    同じ ip_address でアクセスする。

    score が変化しない場合を想定するため、
    疑わしくないアクセスを設定する。
    # $contents の内容
    - 'simple_ua' は空文字ではない。
    - 'is_no_ua' は 0 に設定する。
    - 'is_ua_mismatch' は 0 に設定する。
    - 'recaptcha_solved' は 0 に設定する。
    - 'user_agent' は、set されている。

    # $uaData の内容
    - 'score_session' は、新規アクセスとして、
    0 をセットする。
    - 'score_ip' は、step1 で書き込んだ値をセットする。
    つまり 1
    - 'access_count_session' 
    （過去1分間のアクセス数）
    は新規アクセスとして、0 をセットする。
    - 'access_count_ip' 
    （過去1分間のアクセス数）
    は、step1 で1アクセスしている想定。
    つまり 1
    - 'is_decreased_session' は 0
    - 'is_decreased_ip' は 0
    - 'is_no_anomaly_session' は
    新規アクセスとして、
    過去10分間に疑わしいアクセスがないという想定で
    0、
    で減算対象のロジックが適用されますが、
    新規アクセスの場合 score は 0
    で、ゼロよりも小さい値にはならないため、
    減算は行われません。
    - 'is_no_anomaly_ip' は
    過去10分間に疑わしいアクセスが
    step1 であったという想定で、0

step3: record count が 3 であることを確認する。
    step1: session + ip = 2 レコード INSERT
    step2: session は新規 → INSERT、ip は既存 → UPDATE（増えない）
    合計 3 レコードになることを確認する。
---------------------------------------
*/

// -------------------------------------------------------
// session insert / ip update
// score ip same as previous
//
// このケースでは、
// session base では新規アクセス（→ session は INSERT）
// ip base では過去にアクセスがあり（→ ip は UPDATE）
// かつ ip の score が step1 と step2 で同じ値になる場合を確認します。
//
// SQL の UPDATE では、score が同じ値の場合と異なる値の場合で
// 挙動が変わる可能性があるため、score が同じ場合もテストします。
//
// step 1: CLEAR_DB で insert を行い、scoreSession=1 / scoreIp=1 を書き込む。
//         is_no_ua=1 → score +1 for each subject_type
//         ua=''、simple_ua='' (is_no_ua===1 の場合、simple_ua は '' になる想定)
//
// step 2: 異なる session_id / 同じ ip_address で NOT_CLEAR_DB にして実行する。
//         疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count は閾値未満）
//         is_no_anomaly_ip=0（step1 に疑わしいアクセスがあったため異常あり）→ 減算なし
//         → score_ip = 1 のまま（step1 と同じ値で UPDATE）← このケースのキーポイント
//         session は新規 → INSERT（score=0）
//         ip は既存  → UPDATE（score=1、step1 と同値で UPDATE）
//
// step 3: record count が 3 であることを確認する。
//         step 1 で session(01) + ip = 2 レコード INSERT
//         step 2 で session(02) = 1 レコード INSERT、ip は UPDATE（増えない）
//         合計 3 レコードになることを確認する。
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session insert / ip update (score ip same), step 1: insert (both)';

$contents = [
    'session_id'      => 'score_same_session_01',
    'ip_address'      => '172.18.0.1',
    'simple_ua'       => '',   // is_no_ua が 1 なので、simple_ua は空になる想定
    'is_no_ua'        => 1,    // score +1
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => '',   // ua がセットされていない場合は '' となる
];

$uaData = [
    'score_session'        => 0,  // DB に記録なし → 0
    'score_ip'             => 0,  // DB に記録なし → 0
    'access_count_session' => 0,  // 閾値 60
    'access_count_ip'      => 0,  // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session INSERT / ip UPDATE (NOT_CLEAR_DB)
// score が変化しない場合を想定するため、疑わしくないアクセスを設定する。
// session_id を変える（→ session は新規 INSERT）
// ip_address は step 1 と同じ（→ ip は UPDATE）
// is_no_anomaly_ip=0（step1 に疑わしいアクセスがあったため異常あり）→ 減算なし
// → score_ip = 1 のまま（step1 と同じ値で UPDATE）
$caseLabel = 'Case<br>session insert / ip update (score ip same), step 2: session insert / ip update';

$contents = [
    'session_id'      => 'score_same_session_02',  // step 1 と異なる session_id → session INSERT
    'ip_address'      => '172.18.0.1',              // step 1 と同じ ip_address → ip UPDATE
    'simple_ua'       => 'Chrome/91',               // is_no_ua=0 なので空文字ではない
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,  // 新規セッション → DB に記録なし → 0
    'score_ip'             => 1,  // step 1 で DB に書かれた ip score
    'access_count_session' => 0,  // 新規アクセスとして 0
    'access_count_ip'      => 1,  // step 1 で 1 アクセスしている想定
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 1,  // 新規セッション。で
    // 減算対象になるロジック
    // ですが、
    // ゼロより小さくはならないので、
    // 減算はスキップされます。
    'is_no_anomaly_ip'      => 0,  // step1 に疑わしいアクセスがあったため 0（異常あり）
    // → decreaseScore() で減算されない
    // → score_ip = 1 のまま（step1 と同値で UPDATE）
];

// score 計算:
// session: previous(0) + is_no_ua(0) = 0
//          not suspicious → decrease check
//          is_decreased=0 → is_no_anomaly_session=0 → skip -1
//          recaptcha_solved=0 → skip decrease
//          → score_session = 0
// ip:      previous(1) + is_no_ua(0) = 1
//          not suspicious → decrease check
//          is_decreased=0 → is_no_anomaly_ip=0 → skip -1
//          recaptcha_solved=0 → skip decrease
//          → score_ip = 1（step1 と同じ値のまま UPDATE）← このケースのキーポイント
$scoreSessionExpected = 0;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → ip は UPDATE、session は INSERT になることを確認

// step 3: record count が 3 であることを確認する。
//   step 1: score_same_session_01（session）+ 172.18.0.1（ip）= 2 レコード INSERT
//   step 2: score_same_session_02（session）= 1 レコード INSERT、172.18.0.1（ip）= UPDATE（増えない）
//   合計 3 レコード
$caseLabel = 'Record count = 3: session(01) + ip + session(02) の合計を確認（score ip same）';
$expectedCount = 3;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session update / ip insert
// score session same as previous
//
// このケースでは、
// session base では過去にアクセスがあり（→ session は UPDATE）、
// ip base では新規アクセス（→ ip は INSERT）の場合を確認します。
// さらに、session の score が step1 と step2 で同じ値になる場合を確認します。
//
// SQL の UPDATE では、score が同じ値の場合と異なる値の場合で
// 挙動が変わる可能性があるため、score が同じ場合もテストします。
//
// step 1: CLEAR_DB で insert を行い、scoreSession=1 / scoreIp=1 を書き込む。
//         is_no_ua=1 → score +1 for each subject_type
//         ua=''、simple_ua='' (is_no_ua===1 の場合、simple_ua は '' になる想定)
//
// step 2: 同じ session_id / 異なる ip_address で NOT_CLEAR_DB にして実行する。
//         疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count は閾値未満）
//         is_no_anomaly_session=0（step1 に疑わしいアクセスがあったため異常あり）→ 減算なし
//         → score_session = 1 のまま（step1 と同じ値で UPDATE）← このケースのキーポイント
//         is_no_anomaly_ip=1（新規 IP、異常なし）→ score_ip = 0-1=-1 → max(0) = 0
//         session は既存 → UPDATE（score=1、step1 と同値で UPDATE）
//         ip は新規     → INSERT（score=0）
//
// step 3: record count が 3 であることを確認する。
//         step 1 で session + ip = 2 レコード INSERT
//         step 2 で session = UPDATE（増えない）、ip = 1 レコード INSERT
//         合計 3 レコードになることを確認する。
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session update / ip insert (score session same), step 1: insert (both)';

$contents = [
    'session_id'      => 'ss_same_01',
    'ip_address'      => '172.20.0.1',
    'simple_ua'       => '',   // is_no_ua が 1 なので、simple_ua は空になる想定
    'is_no_ua'        => 1,    // score +1
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => '',   // ua がセットされていない場合は '' となる
];

$uaData = [
    'score_session'        => 0,  // DB に記録なし → 0
    'score_ip'             => 0,  // DB に記録なし → 0
    'access_count_session' => 0,  // 閾値 60
    'access_count_ip'      => 0,  // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session UPDATE / ip INSERT (NOT_CLEAR_DB)
// score が変化しない場合を想定するため、疑わしくないアクセスを設定する。
// session_id は step 1 と同じ（→ session は UPDATE）
// ip_address は step 1 と異なる（→ ip は新規 INSERT）
// is_no_anomaly_session=0（step1 に疑わしいアクセスがあったため異常あり）→ 減算なし
// → score_session = 1 のまま（step1 と同じ値で UPDATE）
// is_no_anomaly_ip=1（新規 IP のため異常なし）
// → score_ip = 0 - 1 = -1 → max(0) = 0
$caseLabel = 'Case<br>session update / ip insert (score session same), step 2: session update / ip insert';

$contents = [
    'session_id'      => 'ss_same_01',      // step 1 と同じ session_id → session UPDATE
    'ip_address'      => '172.20.0.2',      // step 1 と異なる ip_address → ip INSERT
    'simple_ua'       => 'Chrome/91',       // is_no_ua=0 なので空文字ではない
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 1,  // step 1 で DB に書かれた session score
    'score_ip'             => 0,  // 新規 IP → DB に記録なし → 0
    'access_count_session' => 1,  // step 1 で 1 アクセスしている想定
    'access_count_ip'      => 0,  // 新規 IP なのでアクセス履歴なし
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,  // step1 に疑わしいアクセスがあったため 0（異常あり）
    // → decreaseScore() で減算されない
    // → score_session = 1 のまま（step1 と同値で UPDATE）
    'is_no_anomaly_ip'      => 1,  // 新規 IP のため異常なし → is_no_anomaly=1
    // → score_ip = 0 - 1 = -1 → max(0) = 0
    // ゼロより小さくはならないため、実質 0 で確定
];

// score 計算:
// session: previous(1) + is_no_ua(0) = 1
//          not suspicious → decrease check
//          is_decreased=0 → is_no_anomaly_session=0 → skip -1
//          recaptcha_solved=0 → skip decrease
//          → score_session = 1（step1 と同じ値のまま UPDATE）← このケースのキーポイント
// ip:      previous(0) + is_no_ua(0) = 0
//          not suspicious → decrease check
//          is_decreased=0 → is_no_anomaly_ip=1 → score = 0 - 1 = -1 → max(0) = 0
//          → score_ip = 0
$scoreSessionExpected = 1;
$scoreIpExpected      = 0;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → session は UPDATE、ip は INSERT になることを確認

// step 3: record count が 3 であることを確認する。
//   step 1: ss_same_01（session）+ 172.20.0.1（ip）= 2 レコード INSERT
//   step 2: ss_same_01（session）= UPDATE（レコード増えない）、172.20.0.2（ip）= 1 レコード INSERT
//   合計 3 レコード
$caseLabel = 'Record count = 3: session + ip(172.20.0.1) + ip(172.20.0.2) の合計を確認（score session same）';
$expectedCount = 3;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session update / ip update
// 両方の score が step1 と同じ値のまま UPDATE される
//
// [テストの意図]
// SQL の UPDATE では、score が同じ値の場合と異なる値の場合で
// 挙動が変わる可能性があるため、
// session・ip 両方が UPDATE かつ両方の score が変化しない
// ケースもテストする。
//
// step 1: CLEAR_DB
//   is_no_ua=1 (+1) で INSERT → score_session=1, score_ip=1
//
// step 2: NOT_CLEAR_DB（同じ session_id / 同じ ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   加算なし → score = previous のまま
//   is_decreased=0, is_no_anomaly=0, recaptcha_solved=0
//   → 減算なし → score = previous のまま
//   → score_session = 1（step1 と同値で UPDATE）← キーポイント
//   → score_ip      = 1（step1 と同値で UPDATE）← キーポイント
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session update / ip update (both score same), step 1: insert (both)';

$contents = [
    'session_id'       => 'both_same_01',
    'ip_address'       => '172.22.0.1',
    'simple_ua'        => '',    // is_no_ua=1 の場合 simple_ua は '' になる
    'is_no_ua'         => 1,     // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => '',
];

$uaData = [
    'score_session'         => 0,  // DB に記録なし → 0
    'score_ip'              => 0,  // DB に記録なし → 0
    'access_count_session'  => 0,  // 閾値 60
    'access_count_ip'       => 0,  // 閾値 600
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session UPDATE / ip UPDATE、両方の score が変化しないことを確認する (NOT_CLEAR_DB)
// session_id は step 1 と同じ（→ session は UPDATE）
// ip_address は step 1 と同じ（→ ip は UPDATE）
// 疑わしくないアクセス、加算・減算なし → score = previous のまま
$caseLabel = 'Case<br>session update / ip update (both score same), step 2: both UPDATE, both score unchanged';

$contents = [
    'session_id'       => 'both_same_01',   // step 1 と同じ → session UPDATE
    'ip_address'       => '172.22.0.1',     // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',      // is_no_ua=0 なので空文字ではない
    'is_no_ua'         => 0,    // 疑わしくない
    'is_ua_mismatch'   => 0,    // 疑わしくない
    'recaptcha_solved'  => 0,   // 分岐4 を混在させない
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 1,  // step 1 で DB に書かれたスコア
    'score_ip'              => 1,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 1,  // step 1 で 1 アクセスしている想定
    'access_count_ip'       => 1,  // 同上
    'is_decreased_session'  => 0,  // 分岐2 をスキップ
    'is_decreased_ip'       => 0,  // 同上
    'is_no_anomaly_session' => 0,  // step1 に疑わしいアクセスがあったため 0（異常あり）
    // → 分岐3 スキップ → score_session = 1 のまま
    'is_no_anomaly_ip'      => 0,  // 同上 → score_ip = 1 のまま
];

// スコア計算:
// session: previous(1) + 加算なし(0) = 1
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=0 → 分岐4 スキップ
//          → score_session = 1（step1 と同値のまま UPDATE）← このテストのキーポイント
// ip:      同様に → score_ip = 1（step1 と同値のまま UPDATE）← このテストのキーポイント
$scoreSessionExpected = 1;  // step1 と同値での UPDATE
$scoreIpExpected      = 1;  // step1 と同値での UPDATE

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: both_same_01 テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session update (score change) / ip update (score same)
// 混在パターン:
//   session は既存レコードの UPDATEかつスコアが変化する
//   ip     は既存レコードの UPDATEかつスコアが同値のまま
//
// [テストの意図]
// score の変化が session 側だけに起き、ip 側は変化しない
// ケースを確認する。
//
// スコア分離の設計:
//   access_count_session = JUST_THRESHOLD_SESSION
//   → isOverThresholdSession=1 → score_session += 3
//   access_count_ip = 0 (< 閾値)
//   → isOverThresholdIp=0 → score_ip += 0
//
// step 1: CLEAR_DB
//   is_no_ua=1 (+1) で INSERT → score_session=1, score_ip=1
//
// step 2: NOT_CLEAR_DB（同じ session_id / 同じ ip_address → 両方 UPDATE）
//   access_count_session = JUST_THRESHOLD_SESSION
//   → isOverThresholdSession=1 → session 疑わしいアクセス、score_session += 3 → 1+3=4（変化）
//   access_count_ip = 0 (< 閾値)
//   → isOverThresholdIp=0 → ip は疑わしくない、加算なし
//   ip: 減算なし (is_no_anomaly=0, recaptcha=0) → score_ip = 1 のまま（同値）
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session update (score change) / ip update (score same), step 1: insert (both)';

$contents = [
    'session_id'       => 'mix_score_change_01',
    'ip_address'       => '172.24.0.1',
    'simple_ua'        => '',    // is_no_ua=1 の場合 simple_ua は '' になる
    'is_no_ua'         => 1,     // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => '',
];

$uaData = [
    'score_session'         => 0,  // DB に記録なし → 0
    'score_ip'              => 0,  // DB に記録なし → 0
    'access_count_session'  => 0,  // 閾値 60
    'access_count_ip'       => 0,  // 閾値 600
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session UPDATE (score change) / ip UPDATE (score same) (NOT_CLEAR_DB)
// session_id は step 1 と同じ（→ session は UPDATE）
// ip_address は step 1 と同じ（→ ip は UPDATE）
//
// スコア分離のポイント:
//   access_count_session = JUST_THRESHOLD_SESSION
//   → isOverThresholdSession=1 → session のみ +3（session だけ疑わしいアクセス）
//   access_count_ip = 0
//   → isOverThresholdIp=0 → ip は +0（ip は疑わしくない）
$caseLabel = 'Case<br>session update (score change) / ip update (score same), step 2: session(1+3=4), ip(1 同値)';

$contents = [
    'session_id'       => 'mix_score_change_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '172.24.0.1',            // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',             // is_no_ua=0 なので空文字ではない
    'is_no_ua'         => 0,    // 疑わしくない（is_ua_mismatch=0 とセットで加算なし）
    'is_ua_mismatch'   => 0,    // 疑わしくない
    'recaptcha_solved'  => 0,   // 分岐4 を混在させない
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 1,  // step 1 で DB に書かれたスコア
    'score_ip'              => 1,  // step 1 で DB に書かれたスコア
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値(60) → isOverThresholdSession=1
    // → session 疑わしい → score +3
    'access_count_ip'       => 0,   // 閾値(600)未満 → isOverThresholdIp=0
    // → ip は疑わしくない → 加算なし
    'is_decreased_session'  => 0,   // 分岐2 は考慮不要（session は疑わしいアクセスのため減算㏙スキップ）
    'is_decreased_ip'       => 0,   // ip は分岐2 をスキップ
    'is_no_anomaly_session' => 0,   // session は疑わしいアクセスのため履歴あり、分岐1 早期リターン
    'is_no_anomaly_ip'      => 0,   // step1 に疑わしいアクセスがあったため 0
    // → 分岐3 スキップ → score_ip = 1 のまま
];

// スコア計算:
// session: previous(1) + over_threshold_session(+3) = 4
//          isOverThresholdSession=1 → isSuspiciousAccess=1
//          → decreaseScore() 分岐1: 早期リターン → 減算なし
//          → score_session = 4（step1 の 1 から変化）← このテストのキーポイント
//
// ip:      previous(1) + 加算なし(0) = 1
//          isOverThresholdIp=0 → isSuspiciousAccess=0 for ip
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=0 → 分岐3 スキップ
//          recaptcha_solved=0 → 分岐4 スキップ
//          → score_ip = 1（step1 と同値のまま UPDATE）← このテストのキーポイント
$scoreSessionExpected = 4;  // 1 + over_threshold_session(+3) = 4（変化）
$scoreIpExpected      = 1;  // step1 と同値のまま UPDATE（同値）

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: mix_score_change_01 テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// session update (score same) / ip update (score change)
// 混在パターン（前のテストの鎖形）:
//   session は既存レコードの UPDATE かつスコアが同値のまま
//   ip     は既存レコードの UPDATE かつスコアが変化する
//
// [テストの意図]
// 前のテストでは session 側の score が変化し、ip 側が同値だった。
// このテストは逆パターンで、ip 側の score が変化し、session 側が同値であることを確認する。
//
// スコア分離の設計（前テストの鎖形）:
//   access_count_ip = JUST_THRESHOLD_IP
//   → isOverThresholdIp=1 → score_ip += 3（ip のみ疑わしいアクセス）
//   access_count_session = 0 (< 閾値)
//   → isOverThresholdSession=0 → score_session += 0
//
// step 1: CLEAR_DB
//   is_no_ua=1 (+1) で INSERT → score_session=1, score_ip=1
//
// step 2: NOT_CLEAR_DB（同じ session_id / 同じ ip_address → 両方 UPDATE）
//   access_count_ip = JUST_THRESHOLD_IP
//   → isOverThresholdIp=1 → ip 疑わしいアクセス、score_ip += 3 → 1+3=4（変化）
//   access_count_session = 0 (< 閾値)
//   → isOverThresholdSession=0 → session は疑わしくない、加算なし
//   session: 減算なし (is_no_anomaly=0, recaptcha=0) → score_session = 1 のまま（同値）
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
$caseLabel = 'Case<br>session update (score same) / ip update (score change), step 1: insert (both)';

$contents = [
    'session_id'       => 'mix_ip_change_01',
    'ip_address'       => '172.26.0.1',
    'simple_ua'        => '',    // is_no_ua=1 の場合 simple_ua は '' になる
    'is_no_ua'         => 1,     // score +1
    'is_ua_mismatch'   => 0,
    'recaptcha_solved'  => 0,
    'user_agent'       => '',
];

$uaData = [
    'score_session'         => 0,  // DB に記録なし → 0
    'score_ip'              => 0,  // DB に記録なし → 0
    'access_count_session'  => 0,  // 閾値 60
    'access_count_ip'       => 0,  // 閾値 600
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_no_ua=1 → isSuspiciousAccess=1 → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// 計算: previous(0) + is_no_ua(+1) = 1
// 減算: is_no_ua===1 → isSuspiciousAccess===1 → decreaseScore() 早期リターン
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: session UPDATE (score same) / ip UPDATE (score change) (NOT_CLEAR_DB)
// session_id は step 1 と同じ（→ session は UPDATE）
// ip_address は step 1 と同じ（→ ip は UPDATE）
//
// スコア分離のポイント（前テストの鎖形）:
//   access_count_ip = JUST_THRESHOLD_IP
//   → isOverThresholdIp=1 → ip のみ +3（ip だけ疑わしいアクセス）
//   access_count_session = 0
//   → isOverThresholdSession=0 → session は +0（session は疑わしくない）
$caseLabel = 'Case<br>session update (score same) / ip update (score change), step 2: session(1 同値), ip(1+3=4)';

$contents = [
    'session_id'       => 'mix_ip_change_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '172.26.0.1',         // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',          // is_no_ua=0 なので空文字ではない
    'is_no_ua'         => 0,    // 疑わしくない（is_ua_mismatch=0 とセットで加算なし）
    'is_ua_mismatch'   => 0,    // 疑わしくない
    'recaptcha_solved'  => 0,   // 分岐4 を混在させない
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 1,  // step 1 で DB に書かれたスコア
    'score_ip'              => 1,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 0,   // 閾値(60)未満 → isOverThresholdSession=0
    // → session は疑わしくない → 加算なし
    'access_count_ip'       => JUST_THRESHOLD_IP,  // 閾値(600) → isOverThresholdIp=1
    // → ip 疑わしいアクセス → score +3
    'is_decreased_session'  => 0,   // ip は疑わしいアクセスのため減算スキップ
    'is_decreased_ip'       => 0,   // session は分岐2 をスキップ
    'is_no_anomaly_session' => 0,   // step1 に疑わしいアクセスがあったため 0
    // → 分岐3 スキップ → score_session = 1 のまま
    'is_no_anomaly_ip'      => 0,   // ip は疑わしいアクセスのため履歴あり、分岐1 早期リターン
];

// スコア計算:
// session: previous(1) + 加算なし(0) = 1
//          isOverThresholdSession=0 → isSuspiciousAccess=0 for session
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=0 → 分岐4 スキップ
//          → score_session = 1（step1 と同値のまま UPDATE）← このテストのキーポイント
//
// ip:      previous(1) + over_threshold_ip(+3) = 4
//          isOverThresholdIp=1 → isSuspiciousAccess=1
//          → decreaseScore() 分岐1: 早期リターン → 減算なし
//          → score_ip = 4（step1 の 1 から変化）← このテストのキーポイント
$scoreSessionExpected = 1;  // step1 と同値のまま UPDATE（同値）
$scoreIpExpected      = 4;  // 1 + over_threshold_ip(+3) = 4（変化）

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: mix_ip_change_01 テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// 以下は境界値テストです。

/* session ベースの過去1分間のアクセス数が閾値-1の場合のテスト */
$caseLabel = 'Case<br>session ベースの過去1分間のアクセス数が閾値-1の場合のテスト';
$contents = [
    'session_id'      => 'session_threshold_minus_1',
    'ip_address'      => '192.168.0.1',
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => JUST_THRESHOLD_SESSION - 1, // 閾値-1
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip' => 0
];
$is_over_threshold_session = 0; // 閾値-1なので、閾値を超えていない
$is_over_threshold_ip = 0; // 閾値 600 なので、閾値を超えていない

$scoreSessionExpected = 0; // previous score 0、加算なし、減算なし → score = 0
$scoreIpExpected = 0; // previous score 0、加算なし、減算なし → score = 0

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

//  checkRecordCount() の引数を定義します。
$caseLabel = 'Check record count after session threshold-1 test';
$expectedCount = 2; // session と ip の2件が挿入されることを期待します。
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* session ベースの過去1分間のアクセス数が閾値の場合のテスト */
$caseLabel = 'Case<br>session ベースの過去1分間のアクセス数が閾値の場合のテスト';
$contents = [
    'session_id'       => 'session_threshold',
    'ip_address'       => '192.168.0.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 0,
    'recaptcha_solved' => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => JUST_THRESHOLD_SESSION, // 閾値
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip' => 0
];

$is_over_threshold_session = 1; // 閾値なので、閾値を超えている
$is_over_threshold_ip = 0; // 閾値 600 なので、閾値を超えていない

$scoreSessionExpected = 3; // previous score 0、加算 +3、減算なし → score = 3
$scoreIpExpected = 0; // previous score 0、加算なし、減算なし → score = 0

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

//  checkRecordCount() の引数を定義します。
$caseLabel = 'Check record count after session threshold test';
$expectedCount = 2; // session と ip の2件が挿入されることを期待します。
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* session ベースの過去1分間のアクセス数が閾値+1の場合のテスト */
$caseLabel = 'Case<br>session ベースの過去1分間のアクセス数が閾値+1の場合のテスト';
$contents = [
    'session_id'       => 'session_threshold_plus_1',
    'ip_address'       => '192.168.0.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 0,
    'recaptcha_solved' => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => JUST_THRESHOLD_SESSION + 1, // 閾値+1
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip' => 0
];

$is_over_threshold_session = 1; // 閾値+1なので、閾値を超えている
$is_over_threshold_ip = 0; // 閾値 600 なので、閾値を超えていない

$scoreSessionExpected = 3; // previous score 0、加算 +3、減算なし → score = 3
$scoreIpExpected = 0; // previous score 0、加算なし、減算なし → score = 0

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

//  checkRecordCount() の引数を定義します。
$caseLabel = 'Check record count after session threshold+1 test';
$expectedCount = 2; // session と ip の2件が挿入されることを期待します。
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* IP ベースの過去1分間のアクセス数が閾値-1の場合のテスト */
$caseLabel = 'Case<br>IP ベースの過去1分間のアクセス数が閾値-1の場合のテスト (599)';
$contents = [
    'session_id'       => 'ip_threshold_minus_1',
    'ip_address'       => '10.0.1.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 0,
    'recaptcha_solved' => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,
    'score_ip'             => 0,
    'access_count_session' => 0,                      // 閾値 60
    'access_count_ip'      => JUST_THRESHOLD_IP - 1,  // 閾値-1 (599)
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip'      => 0,
];

$is_over_threshold_session = 0; // 閾値を超えていない
$is_over_threshold_ip      = 0; // 閾値-1なので、閾値を超えていない

/* score calculation
previous score 0

is_no_ua 0 => 加算なし

ua があるので比較できるが、
is_ua_mismatch 0 => 加算なし

過去1分の ip アクセス数が閾値を超えていないので、
加算なし

疑わしいアクセスではない

過去30分にスコアが減点されたアクセスがない、

過去10分に異常がなかったという
記録はないので、
減点しません。

recaptcha_solved 0 なので、
減算しません。
結果は、
session score は 0、ip score は 0 です。
*/
$scoreSessionExpected = 0;
$scoreIpExpected      = 0;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

$caseLabel = 'Check record count after IP threshold-1 test';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* IP ベースの過去1分間のアクセス数が閾値の場合のテスト */
$caseLabel = 'Case<br>IP ベースの過去1分間のアクセス数が閾値の場合のテスト (600)';
$contents = [
    'session_id'       => 'ip_threshold',
    'ip_address'       => '10.0.1.2',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 0,
    'recaptcha_solved' => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,
    'score_ip'             => 0,
    'access_count_session' => 0,                  // 閾値 60
    'access_count_ip'      => JUST_THRESHOLD_IP,  // 閾値 (600)
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip'      => 0,
];

$is_over_threshold_session = 0; // 閾値を超えていない
$is_over_threshold_ip      = 1; // 閾値なので、閾値を超えている

/* score calculation
previous score 0

is_no_ua 0 => 加算なし

ua があるので比較できるが、
is_ua_mismatch 0 => 加算なし

過去1分の ip アクセス数が閾値を超えているので、
ip score に +3

ip が疑わしいアクセス (is_over_threshold_ip === 1) なので、
ip の減算ロジックは適用されず、加算後のスコアが計算結果となります。

session は疑わしいアクセスではない (is_no_ua=0, is_ua_mismatch=0, is_over_threshold_session=0)
過去30分にスコアが減点されたアクセスがない、
過去10分に異常がなかったという記録はないので、減点しません。
recaptcha_solved 0 なので、減算しません。

結果は、
session score は 0、ip score は 0 + 3 = 3 です。
*/
$scoreSessionExpected = 0;
$scoreIpExpected      = 3;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

$caseLabel = 'Check record count after IP threshold test';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* IP ベースの過去1分間のアクセス数が閾値+1の場合のテスト */
$caseLabel = 'Case<br>IP ベースの過去1分間のアクセス数が閾値+1の場合のテスト (601)';
$contents = [
    'session_id'       => 'ip_threshold_plus_1',
    'ip_address'       => '10.0.1.3',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 0,
    'recaptcha_solved' => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'        => 0,
    'score_ip'             => 0,
    'access_count_session' => 0,                      // 閾値 60
    'access_count_ip'      => JUST_THRESHOLD_IP + 1,  // 閾値+1 (601)
    'is_decreased_session' => 0,
    'is_decreased_ip'      => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip'      => 0,
];

$is_over_threshold_session = 0; // 閾値を超えていない
$is_over_threshold_ip      = 1; // 閾値+1なので、閾値を超えている

/* score calculation
previous score 0

is_no_ua 0 => 加算なし

ua があるので比較できるが、
is_ua_mismatch 0 => 加算なし

過去1分の ip アクセス数が閾値を超えているので、
ip score に +3

ip が疑わしいアクセス (is_over_threshold_ip === 1) なので、
ip の減算ロジックは適用されず、加算後のスコアが計算結果となります。

session は疑わしいアクセスではない
過去30分にスコアが減点されたアクセスがない、
過去10分に異常がなかったという記録はないので、減点しません。
recaptcha_solved 0 なので、減算しません。

結果は、
session score は 0、ip score は 0 + 3 = 3 です。
*/
$scoreSessionExpected = 0;
$scoreIpExpected      = 3;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

$caseLabel = 'Check record count after IP threshold+1 test';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// 加算ロジック: is_ua_mismatch === 1 単独 → score += 2
//
// [テストの意図]
// is_ua_mismatch=1 のみが score に影響する場合を確認する。
//   - is_no_ua=0（UA あり、比較可能）
//   - is_ua_mismatch=1 → UA 不一致 → score +2
//   - access_count < 閾値 → over_threshold なし（+0）
//
// is_ua_mismatch=1 は isSuspiciousAccess=1 を意味するため、
// 減算ロジックは適用されず、加算後のスコア(+2)が確定する。
//
// expected:
//   score_session = 0 + 2 = 2
//   score_ip      = 0 + 2 = 2
// -------------------------------------------------------
$caseLabel = 'Case<br>加算ロジック: is_ua_mismatch===1 単独 → score += 2';

$contents = [
    'session_id'       => 'ua_mismatch_only',
    'ip_address'       => '192.168.30.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,   // UA あり → is_ua_mismatch が有効
    'is_ua_mismatch'   => 1,   // ← このテストのキーポイント: score +2
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => 0,   // 閾値(60)未満 → isOverThresholdSession=0 → over_threshold 加算なし
    'access_count_ip'       => 0,   // 閾値(600)未満 → isOverThresholdIp=0     → over_threshold 加算なし
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,   // is_ua_mismatch=1 → isSuspiciousAccess=1 → 減算スキップ（参照されない）
    'is_no_anomaly_ip'      => 0,   // 同上
];

// スコア計算:
// session: previous(0) + is_no_ua(0) + ua_mismatch(+2) + over_threshold(0) = 2
//          is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
//          → score_session = 2  ← このテストのキーポイント
// ip:      previous(0) + is_no_ua(0) + ua_mismatch(+2) + over_threshold(0) = 2
//          isSuspiciousAccess=1 → 減算なし
//          → score_ip = 2
$scoreSessionExpected = 2;
$scoreIpExpected      = 2;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

$caseLabel = 'Check record count after is_ua_mismatch===1 単独テスト';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// 加算ロジック: is_no_ua===1 かつ is_ua_mismatch===1 → score += 1 のみ
//
// [テストの意図]
// is_no_ua===1（UA なし）の場合、UA を比較できないため、
// is_ua_mismatch による +2 の加算はスキップされることを確認する。
//
// user_agent_risk_evaluator.php の evaluate() メソッドの加算ロジック:
//   if ($this->isNoUa===1) {
//       $currentScore += 1;          // 常に適用される
//   }
//   if ($this->isUaMismatch===1 and $this->isNoUa !== 1) {  // ← isNoUa===1 のとき条件が偽
//       $currentScore += 2;          // → このブロックはスキップされる
//   }
//
// したがって、is_no_ua===1 かつ is_ua_mismatch===1 の場合:
//   score = 0 + 1 (from is_no_ua) = 1  ← このテストのキーポイント
//   score != 3 （is_no_ua(+1) + is_ua_mismatch(+2) にはならない）
//
// また、is_no_ua===1 は isSuspiciousAccess=1 を意味するため、
// 減算ロジックは適用されず、score = 1 で確定する。
//
// expected:
//   score_session = 0 + 1 = 1
//   score_ip      = 0 + 1 = 1
// -------------------------------------------------------
$caseLabel = 'Case<br>加算ロジック: is_no_ua===1 かつ is_ua_mismatch===1 → is_ua_mismatch を無視し score += 1 のみ';

$contents = [
    'session_id'       => 'no_ua_and_mismatch',
    'ip_address'       => '192.168.31.1',
    'simple_ua'        => '',    // is_no_ua=1 の場合、simple_ua は '' になる
    'is_no_ua'         => 1,     // UA なし → score +1
    'is_ua_mismatch'   => 1,     // UA なしのため比較不能 → 加算スキップ（+0）
    'recaptcha_solved'  => 0,
    'user_agent'       => '',    // UA なしの場合 '' になる
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => 0,   // 閾値(60)未満 → isOverThresholdSession=0 → +0
    'access_count_ip'       => 0,   // 閾値(600)未満 → isOverThresholdIp=0     → +0
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,   // is_no_ua=1 → isSuspiciousAccess=1 → 減算スキップ（参照されない）
    'is_no_anomaly_ip'      => 0,   // 同上
];

// スコア計算（evaluate() のロジックに従う）:
// session:
//   if (isNoUa===1)                        → currentScore += 1  // score = 1
//   if (isUaMismatch===1 and isNoUa !== 1) → 条件が偽 (isNoUa===1 のため)
//                                          → スキップ: +0
//   isOverThresholdSession=0               → +0
//   isSuspiciousAccess=1 (is_no_ua=1)
//   → decreaseScore() 分岐1: 早期リターン → 減算なし
//   → score_session = 1  ← このテストのキーポイント
// ip: 同様に score_ip = 1
//
// もし is_ua_mismatch のガード (isNoUa !== 1) がなければ
// score = 1 + 2 = 3 になるが、このテストは score = 1 を期待することで
// ガードが正しく機能していることを確認する。
$scoreSessionExpected = 1;
$scoreIpExpected      = 1;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

$caseLabel = 'Check record count after is_no_ua===1 かつ is_ua_mismatch===1 テスト';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* `is_ua_mismatch === 1 && is_over_threshold === 1` の複合条件のテスト */
$caseLabel = 'Case<br>is_ua_mismatch === 1 && is_over_threshold === 1 の複合条件のテスト';
$contents = [
    'session_id'       => 'mismatch_and_threshold',
    'ip_address'       => '192.168.0.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 1,
    'recaptcha_solved' => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => JUST_THRESHOLD_SESSION, // 閾値
    'access_count_ip' => JUST_THRESHOLD_IP, // 閾値 
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip' => 0
];

$is_over_threshold_session = 1; // 閾値
$is_over_threshold_ip = 1; // 閾値

/* score calculation
previous score 0、
加算 
    ua mismatch +2
    over threshold +3
減算
    疑わしいアクセス、減算なし
result score = 0 + 2 + 3 = 5
*/
$scoreSessionExpected = 5;
$scoreIpExpected = 5;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

//  checkRecordCount() の引数を定義します。
$caseLabel = 'Check record count after is_ua_mismatch && is_over_threshold test';
$expectedCount = 2; // session と ip の2件が挿入されることを期待します。
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* subject_key の文字列の長さが上限である場合のテスト */
$session_id = str_repeat('a', 128); // 128文字の文字列を生成
$ip_address = str_repeat('b', 128); // 128文字の文字列を生成

$caseLabel = 'Case<br>subject_key 128文字の境界値テスト';
$contents = [
    'session_id'      => $session_id,
    'ip_address'      => $ip_address,
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];
$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => 0, // 閾値 60
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0, // 異常がないアクセスなので、こちらの値はスコアに影響します。
    'is_no_anomaly_ip' => 0       // 異常がないアクセスなので、こちらの値はスコアに影響します。
];

$is_over_threshold_session =
    checkOverThreshold(
        $uaData['access_count_session'],
        JUST_THRESHOLD_SESSION
    );
$is_over_threshold_ip =
    checkOverThreshold(
        $uaData['access_count_ip'],
        JUST_THRESHOLD_IP
    );

/* risk score calculation
table をTRUNCATE したので、

previous score 0

is no ua 0 => 加算なし

ua があるので比較できるが、
is_ua_mismatch 0 => 加算なし

過去1分のアクセス数が閾値を超えていないので、
加算なし

疑わしいアクセスではない

過去30分
にスコアが減点されたアクセスがない、

過去10分に異常がなかったという
記録はないので、
点減しません。

recaptcha_solved 0 なので、
減算しません。
結果は、
score は 0 です。
*/
$scoreSessionExpected = 0;
$scoreIpExpected = 0;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

//  checkRecordCount() の引数を定義します。
$caseLabel = 'Check record count after subject_key 128文字の境界値テスト';
$expectedCount = 2; // session と ip の2件が挿入されることを期待します。
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* session id の文字列の長さが129文字の境界値テスト */
$session_id = str_repeat('a', 129); // 129文字の文字列を生成
$ip_address = str_repeat('b', 129); // 129文字の文字列を生成

$caseLabel = 'Case<br>subject_key 129文字の境界値テスト<br>例外が発生することを期待します。';
$contents = [
    'session_id'      => $session_id,
    'ip_address'      => $ip_address,
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 0,
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];
$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => 0, // 閾値 60
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0,
    'is_decreased_ip' => 0,
    'is_no_anomaly_session' => 0,
    'is_no_anomaly_ip' => 0
];
runTestCaseError(
    $caseLabel,
    $contents,
    $uaData,
    $pdo
);

/* decreaseScore()の分岐テスト カバレッジ一覧

    # decreaseScore()の分岐テスト
    1. isSuspiciousAccess === 1      → return (no decrease)  ✅
    2. decreased_session === 1       → return (no decrease)  ✅
    2. decreased_ip === 1            → return (no decrease)  ✅
    3. isNoAnomaly_session === 1     → score -= 1, return    ✅
    3. isNoAnomaly_ip === 1          → score -= 1, return    ✅
    4. recaptchaSolved === 1         → score -= 4/1, return  ✅
    4. recaptcha session floor clamp → score < 4 → max(0)   ✅
    4. recaptcha ip floor clamp      → score_ip=0, 0-1→0   ✅
    5. else                          → return (no decrease)  ✅

*/

/*-------------------------------------------
test case 
    'decreased_session'=>1
    で score_session が減算されない
    ことを確認するテストケース

    step1: session score 0、ip score 0 の状態で
    'ua_mismatch'=>1  -> score +2
    'over_threshold'=>1 -> score +3
    → score_session = 5、score_ip = 5

    step2: session score 5、ip score 5 の状態で
    疑わしくないアクセス
    （is_no_ua===0, 
    is_ua_mismatch===0,
    recaptcha_solved===1,
    access_count は閾値未満）で
    (is_suspiciousAccess===0)
    'decreased_session'=>1
    を設定して、
    recaptcha_solved===1 で減算される条件を満たすが、
    decreased_session===1 なので、減算されないことを確認する。
    (score_session が減算されないことを確認する。)
*/

// -------------------------------------------------------
// decreased_session === 1 で score_session が減算されないことを確認する
//
// [テストの意図の詳しい説明]
// decreaseScore() メソッドの分岐：
//   1. isSuspiciousAccess === 1  → return（減算なし）
//   2. decreased === 1           → return（減算なし）  ← このテストで分岐2を確認する
//   3. isNoAnomaly === 1         → score -= 1, return
//   4. recaptchaSolved === 1     → score -= DECREASE_SCORE, return
//   5. else                      → return（減算なし）
//
// session 側: is_decreased_session=1 → 分岐2: 早期 return → score_session は減算されない
// ip 側:      is_decreased_ip=0      → 分岐2 を通過 → recaptcha_solved=1 で分岐4 が実行される
//             → score_ip が減算される（対比確認）
//
// step 1: CLEAR_DB
//   ua_mismatch=1 (+2) / over_threshold=1 (+3) で INSERT
//   → score_session = 5, score_ip = 5
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   recaptcha_solved=1（減算条件を満たす）
//   is_decreased_session=1 → score_session 減算なし → score_session = 5（変化なし）
//   is_decreased_ip=0      → recaptcha_solved=1 で減算 → score_ip = 5 - 1 = 4
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// ua_mismatch=1 (+2) と over_threshold=1 (+3) で score = 5 を書き込む
$caseLabel = 'Case<br>decreased_session===1 で減算されない, step 1: ua_mismatch+over_threshold で score=5 を INSERT';

$contents = [
    'session_id'      => 'decreased_session_test_01',
    'ip_address'      => '192.168.20.1',
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 1,   // score +2（session・ip 両方）
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値 (60) → isOverThresholdSession=1 → score +3
    'access_count_ip'       => JUST_THRESHOLD_IP,       // 閾値 (600) → isOverThresholdIp=1 → score +3
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) + over_threshold_session(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) + over_threshold_ip(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
$scoreSessionExpected = 5;
$scoreIpExpected      = 5;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: decreased_session=1 で score_session が減算されないことを確認する (NOT_CLEAR_DB)
// 同じ session_id / ip_address → 両方 UPDATE
$caseLabel = 'Case<br>decreased_session===1 で減算されない, step 2: decreased_session=1 → score_session 減算なし（score=5 のまま）';

$contents = [
    'session_id'      => 'decreased_session_test_01',  // step 1 と同じ → session UPDATE
    'ip_address'      => '192.168.20.1',               // step 1 と同じ → ip UPDATE
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,  // 疑わしくない
    'is_ua_mismatch'  => 0,  // 疑わしくない
    'recaptcha_solved' => 1, // 減算条件を満たす（decreased がなければ分岐4 で減算される）
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 5,  // step 1 で DB に書かれたスコア
    'score_ip'              => 5,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 1,  // ← このテストのキーポイント
    // 分岐2: decreased===1 → decreaseScore() 早期リターン
    // recaptcha_solved=1 の条件があっても減算されない
    'is_decreased_ip'       => 0,  // ip 側は decreased なし → 減算ロジックを続行
    'is_no_anomaly_session' => 0,  // is_decreased_session=1 で早期リターンするため参照されない
    'is_no_anomaly_ip'      => 0,  // is_no_anomaly=0 → 分岐3 スキップ → 分岐4（recaptcha_solved）へ
];

// スコア計算:
// session: previous(5) + 加算なし = 5
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=1 → 分岐2: decreased===1 → 早期リターン
//          → score_session = 5（減算されない）← このテストのキーポイント
//
// ip:      previous(5) + 加算なし = 5
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_IP(1) → 5 - 1 = 4
//          → score_ip = 4
//          （is_decreased_ip=0 の場合は recaptcha_solved=1 で減算されることを対比確認）
$scoreSessionExpected = 5;  // decreased_session=1 のため減算されない
$scoreIpExpected      = 4;  // decreased_ip=0 + recaptcha_solved=1 → -DECREASE_SCORE_IP(1) → 5-1=4

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: decreased_session テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

/*-------------------------------------------
test case 
    [test 概要]
    'decreased_ip'=>1
    で score_ip が減算されない
    ことを確認するテストケース

    step1: session score 0、ip score 0 の状態で
    'ua_mismatch'=>1  -> score +2
    'over_threshold'=>1 -> score +3
    → score_session = 5、score_ip = 5

    step2: session score 5、ip score 5 の状態で
    疑わしくないアクセス
    （is_no_ua===0, 
    is_ua_mismatch===0,
    recaptcha_solved===1,
    access_count は閾値未満）で
    (is_suspiciousAccess===0)
    'decreased_ip'=>1
    を設定して、
    recaptcha_solved===1 で減算される条件を満たすが、
    decreased_ip===1 なので、減算されないことを確認する。
    (score_ip が減算されないことを確認する。)
 */

// -------------------------------------------------------
// decreased_ip === 1 で score_ip が減算されないことを確認する
//
// [テストの意図]
// decreaseScore() メソッドの分岐：
//   1. isSuspiciousAccess === 1  → return（減算なし）
//   2. decreased === 1           → return（減算なし）  ← このテストで分岐2を確認する
//   3. isNoAnomaly === 1         → score -= 1, return
//   4. recaptchaSolved === 1     → score -= DECREASE_SCORE, return
//   5. else                      → return（減算なし）
//
// ip 側:      is_decreased_ip=1 → 分岐2: 早期 return → score_ip は減算されない
// session 側: is_decreased_session=0 → 分岐2 を通過 → recaptcha_solved=1 で分岐4 が実行される
//             → score_session が減算される（対比確認）
//
// step 1: CLEAR_DB
//   ua_mismatch=1 (+2) / over_threshold=1 (+3) で INSERT
//   → score_session = 5, score_ip = 5
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   recaptcha_solved=1（減算条件を満たす）
//   is_decreased_ip=1      → score_ip 減算なし → score_ip = 5（変化なし）
//   is_decreased_session=0 → recaptcha_solved=1 で減算 → score_session = 5 - 4 = 1
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// ua_mismatch=1 (+2) と over_threshold=1 (+3) で score = 5 を書き込む
$caseLabel = 'Case<br>decreased_ip===1 で減算されない, step 1: ua_mismatch+over_threshold で score=5 を INSERT';

$contents = [
    'session_id'      => 'decreased_ip_test_01',
    'ip_address'      => '192.168.21.1',
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,
    'is_ua_mismatch'  => 1,   // score +2（session・ip 両方）
    'recaptcha_solved' => 0,
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値 (60) → isOverThresholdSession=1 → score +3
    'access_count_ip'       => JUST_THRESHOLD_IP,       // 閾値 (600) → isOverThresholdIp=1 → score +3
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) + over_threshold_session(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) + over_threshold_ip(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
$scoreSessionExpected = 5;
$scoreIpExpected      = 5;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: decreased_ip=1 で score_ip が減算されないことを確認する (NOT_CLEAR_DB)
// 同じ session_id / ip_address → 両方 UPDATE
$caseLabel = 'Case<br>decreased_ip===1 で減算されない, step 2: decreased_ip=1 → score_ip 減算なし（score=5 のまま）';

$contents = [
    'session_id'      => 'decreased_ip_test_01',  // step 1 と同じ → session UPDATE
    'ip_address'      => '192.168.21.1',           // step 1 と同じ → ip UPDATE
    'simple_ua'       => 'Chrome/91',
    'is_no_ua'        => 0,  // 疑わしくない
    'is_ua_mismatch'  => 0,  // 疑わしくない
    'recaptcha_solved' => 1, // 減算条件を満たす（decreased がなければ分岐4 で減算される）
    'user_agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 5,  // step 1 で DB に書かれたスコア
    'score_ip'              => 5,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 0,  // session 側は decreased なし → 減算ロジックを続行
    'is_decreased_ip'       => 1,  // ← このテストのキーポイント
    // 分岐2: decreased===1 → decreaseScore() 早期リターン
    // recaptcha_solved=1 の条件があっても減算されない
    'is_no_anomaly_session' => 0,  // is_no_anomaly=0 → 分岐3 スキップ → 分岐4（recaptcha_solved）へ
    'is_no_anomaly_ip'      => 0,  // is_decreased_ip=1 で早期リターンするため参照されない
];

// スコア計算:
// session: previous(5) + 加算なし = 5
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_SESSION(4) → 5 - 4 = 1
//          → score_session = 1
//          （is_decreased_session=0 の場合は recaptcha_solved=1 で減算されることを対比確認）
//
// ip:      previous(5) + 加算なし = 5
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=1 → 分岐2: decreased===1 → 早期リターン
//          → score_ip = 5（減算されない）← このテストのキーポイント
$scoreSessionExpected = 1;  // decreased_session=0 + recaptcha_solved=1 → -DECREASE_SCORE_SESSION(4) → 5-4=1
$scoreIpExpected      = 5;  // decreased_ip=1 のため減算されない

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: decreased_ip テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// is_no_anomaly_session === 1 で score_session が減算されることを確認する
//
// [テストの意図の詳しい説明]
// decreaseScore() メソッドの分岐：
//   1. isSuspiciousAccess === 1  → return（減算なし）
//   2. decreased === 1           → return（減算なし）
//   3. isNoAnomaly === 1         → score -= 1, return  ← このテストで分岐3を確認する
//   4. recaptchaSolved === 1     → score -= DECREASE_SCORE, return
//   5. else                      → return（減算なし）
//
// session 側: is_no_anomaly_session=1 → 分岐3: score -= 1 = 4  ← このテストのキーポイント
// ip 側:      is_no_anomaly_ip=0      → 分岐3 をスキップ → score_ip は減算されない（対比確認）
//
// step 1: CLEAR_DB
//   ua_mismatch=1 (+2) / over_threshold=1 (+3) で INSERT
//   → score_session = 5, score_ip = 5
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   recaptcha_solved=0（分岐4 を混在させないため 0 に設定する）
//   is_no_anomaly_session=1 → 分岐3: score_session -= 1 → score_session = 4
//   is_no_anomaly_ip=0      → 分岐3 スキップ → score_ip = 5（変化なし）
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// ua_mismatch=1 (+2) と over_threshold=1 (+3) で score = 5 を書き込む
$caseLabel = 'Case<br>is_no_anomaly_session===1 で減算される, step 1: ua_mismatch+over_threshold で score=5 を INSERT';

$contents = [
    'session_id'       => 'no_anomaly_session_test_01',
    'ip_address'       => '192.168.22.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 1,   // score +2（session・ip 両方）
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値 (60) → isOverThresholdSession=1 → score +3
    'access_count_ip'       => JUST_THRESHOLD_IP,       // 閾値 (600) → isOverThresholdIp=1 → score +3
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) + over_threshold_session(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) + over_threshold_ip(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
$scoreSessionExpected = 5;
$scoreIpExpected      = 5;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: is_no_anomaly_session=1 で score_session が減算されることを確認する (NOT_CLEAR_DB)
// 同じ session_id / ip_address → 両方 UPDATE
$caseLabel = 'Case<br>is_no_anomaly_session===1 で減算される, step 2: is_no_anomaly_session=1 → score_session -= 1（5→4）';

$contents = [
    'session_id'       => 'no_anomaly_session_test_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '192.168.22.1',                // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,  // 疑わしくない
    'is_ua_mismatch'   => 0,  // 疑わしくない
    'recaptcha_solved'  => 0, // 分岐4 を混在させないため 0 に設定する
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 5,  // step 1 で DB に書かれたスコア
    'score_ip'              => 5,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 0,  // 分岐2 をスキップし、分岐3 を確認するため 0 に設定する
    'is_decreased_ip'       => 0,  // 同上
    'is_no_anomaly_session' => 1,  // ← このテストのキーポイント
    // 分岐3: isNoAnomaly===1 → score -= 1 = 4, return
    'is_no_anomaly_ip'      => 0,  // 分岐3 をスキップ → recaptcha_solved=0 → 分岐4 スキップ
    // → score_ip = 5（変化なし）← session との対比確認
];

// スコア計算:
// session: previous(5) + 加算なし = 5
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=1 → 分岐3: score -= 1 → 5 - 1 = 4, return
//          → score_session = 4  ← このテストのキーポイント
//
// ip:      previous(5) + 加算なし = 5
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=0 → 分岐3 スキップ
//          recaptcha_solved=0 → 分岐4 スキップ
//          → score_ip = 5（変化なし）← is_no_anomaly_ip=0 の場合は減算されないことを対比確認
$scoreSessionExpected = 4;  // is_no_anomaly_session=1 → 分岐3: score -= 1 → 5 - 1 = 4
$scoreIpExpected      = 5;  // is_no_anomaly_ip=0 のため減算されない

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: is_no_anomaly_session テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// is_no_anomaly_ip === 1 で score_ip が減算されることを確認する
//
// [テストの意図の詳しい説明]
// decreaseScore() メソッドの分岐：
//   1. isSuspiciousAccess === 1  → return（減算なし）
//   2. decreased === 1           → return（減算なし）
//   3. isNoAnomaly === 1         → score -= 1, return  ← このテストで分岐3を確認する
//   4. recaptchaSolved === 1     → score -= DECREASE_SCORE, return
//   5. else                      → return（減算なし）
//
// ip 側:      is_no_anomaly_ip=1 → 分岐3: score -= 1 = 4  ← このテストのキーポイント
// session 側: is_no_anomaly_session=0 → 分岐3 をスキップ → score_session は減算されない（対比確認）
//
// step 1: CLEAR_DB
//   ua_mismatch=1 (+2) / over_threshold=1 (+3) で INSERT
//   → score_session = 5, score_ip = 5
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   recaptcha_solved=0（分岐4 を混在させないため 0 に設定する）
//   is_no_anomaly_session=0 → 分岐3 スキップ → score_session = 5（変化なし）
//   is_no_anomaly_ip=1      → 分岐3: score_ip -= 1 → score_ip = 4
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// ua_mismatch=1 (+2) と over_threshold=1 (+3) で score = 5 を書き込む
$caseLabel = 'Case<br>is_no_anomaly_ip===1 で減算される, step 1: ua_mismatch+over_threshold で score=5 を INSERT';

$contents = [
    'session_id'       => 'no_anomaly_ip_test_01',
    'ip_address'       => '192.168.23.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 1,   // score +2（session・ip 両方）
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値 (60) → isOverThresholdSession=1 → score +3
    'access_count_ip'       => JUST_THRESHOLD_IP,       // 閾値 (600) → isOverThresholdIp=1 → score +3
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) + over_threshold_session(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) + over_threshold_ip(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
$scoreSessionExpected = 5;
$scoreIpExpected      = 5;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: is_no_anomaly_ip=1 で score_ip が減算されることを確認する (NOT_CLEAR_DB)
// 同じ session_id / ip_address → 両方 UPDATE
$caseLabel = 'Case<br>is_no_anomaly_ip===1 で減算される, step 2: is_no_anomaly_ip=1 → score_ip -= 1（5→4）';

$contents = [
    'session_id'       => 'no_anomaly_ip_test_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '192.168.23.1',            // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,  // 疑わしくない
    'is_ua_mismatch'   => 0,  // 疑わしくない
    'recaptcha_solved'  => 0, // 分岐4 を混在させないため 0 に設定する
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 5,  // step 1 で DB に書かれたスコア
    'score_ip'              => 5,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 0,  // 分岐2 をスキップし、分岐3 を確認するため 0 に設定する
    'is_decreased_ip'       => 0,  // 同上
    'is_no_anomaly_session' => 0,  // 分岐3 をスキップ → recaptcha_solved=0 → 分岐4 スキップ
    // → score_session = 5（変化なし）← ip との対比確認
    'is_no_anomaly_ip'      => 1,  // ← このテストのキーポイント
    // 分岐3: isNoAnomaly===1 → score -= 1 = 4, return
];

// スコア計算:
// session: previous(5) + 加算なし = 5
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=0 → 分岐4 スキップ
//          → score_session = 5（変化なし）← is_no_anomaly_session=0 の場合は減算されないことを対比確認
//
// ip:      previous(5) + 加算なし = 5
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=1 → 分岐3: score -= 1 → 5 - 1 = 4, return
//          → score_ip = 4  ← このテストのキーポイント
$scoreSessionExpected = 5;  // is_no_anomaly_session=0 のため減算されない
$scoreIpExpected      = 4;  // is_no_anomaly_ip=1 → 分岐3: score -= 1 → 5 - 1 = 4

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: is_no_anomaly_ip テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

/* 
test case 
    recaptcha_solved===1 で score が減算されることを確認するテストケース
    step1: session score 0、ip score 0 の状態で
    'ua_mismatch'=>1  -> score +2
    'over_threshold'=>1 -> score +3
    → score_session = 5、score_ip = 5

    step2: session score 5、ip score 5 の状態で
    疑わしくないアクセス
    （is_no_ua===0, is_ua_mismatch===0, access_count < 閾値）
    recaptcha_solved===1 で減算されることを確認する。
    expected: score_session = 5 - DECREASE_SCORE_SESSION(4) = 1
              score_ip = 5 - DECREASE_SCORE_IP(1) = 4

    step3: record count が 2（INSERT でなく UPDATE）であることを確認する
*/

// -------------------------------------------------------
// recaptcha_solved === 1 で score が減算されることを確認する
//
// [テストの意図の詳しい説明]
// decreaseScore() メソッドの分岐：
//   1. isSuspiciousAccess === 1  → return（減算なし）
//   2. decreased === 1           → return（減算なし）
//   3. isNoAnomaly === 1         → score -= 1, return
//   4. recaptchaSolved === 1     → score -= DECREASE_SCORE, return  ← このテストで分岐4を確認する
//   5. else                      → return（減算なし）
//
// session 側: recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_SESSION(4) → 5 - 4 = 1
// ip 側:      recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_IP(1)      → 5 - 1 = 4
//
// step 1: CLEAR_DB
//   ua_mismatch=1 (+2) / over_threshold=1 (+3) で INSERT
//   → score_session = 5, score_ip = 5
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   is_decreased_*=0（分岐2 をスキップ）
//   is_no_anomaly_*=0（分岐3 をスキップ）
//   recaptcha_solved=1 → 分岐4: session -= 4, ip -= 1
//   → score_session = 1, score_ip = 4
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// ua_mismatch=1 (+2) と over_threshold=1 (+3) で score = 5 を書き込む
$caseLabel = 'Case<br>recaptcha_solved===1 で減算される, step 1: ua_mismatch+over_threshold で score=5 を INSERT';

$contents = [
    'session_id'       => 'recaptcha_solved_test_01',
    'ip_address'       => '192.168.24.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 1,   // score +2（session・ip 両方）
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値 (60) → isOverThresholdSession=1 → score +3
    'access_count_ip'       => JUST_THRESHOLD_IP,       // 閾値 (600) → isOverThresholdIp=1 → score +3
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) + over_threshold_session(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) + over_threshold_ip(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
$scoreSessionExpected = 5;
$scoreIpExpected      = 5;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: recaptcha_solved=1 で score が減算されることを確認する (NOT_CLEAR_DB)
// 同じ session_id / ip_address → 両方 UPDATE
$caseLabel = 'Case<br>recaptcha_solved===1 で減算される, step 2: recaptcha_solved=1 → session -= 4（5→1）, ip -= 1（5→4）';

$contents = [
    'session_id'       => 'recaptcha_solved_test_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '192.168.24.1',               // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,  // 疑わしくない
    'is_ua_mismatch'   => 0,  // 疑わしくない
    'recaptcha_solved'  => 1, // ← このテストのキーポイント: 分岐4 を実行する
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 5,  // step 1 で DB に書かれたスコア
    'score_ip'              => 5,  // step 1 で DB に書かれたスコア
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 0,  // 分岐2 をスキップするため 0 に設定する
    'is_decreased_ip'       => 0,  // 同上
    'is_no_anomaly_session' => 0,  // 分岐3 をスキップするため 0 に設定する
    'is_no_anomaly_ip'      => 0,  // 同上
    // → 分岐4（recaptcha_solved）へ進む
];

// スコア計算:
// session: previous(5) + 加算なし = 5
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_SESSION(4) → 5 - 4 = 1
//          → score_session = 1  ← このテストのキーポイント
//
// ip:      previous(5) + 加算なし = 5
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_IP(1) → 5 - 1 = 4
//          → score_ip = 4  ← このテストのキーポイント
$scoreSessionExpected = 1;  // 5 - DECREASE_SCORE_SESSION(4) = 1
$scoreIpExpected      = 4;  // 5 - DECREASE_SCORE_IP(1) = 4

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: recaptcha_solved テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);


// -------------------------------------------------------
// recaptcha_solved === 1 かつ session score < DECREASE_SCORE_SESSION(4) のとき
// 減算結果が負になるため max(0) でクランプされることを確認する
//
// [テストの意図の詳しい説明]
// decreaseScore() メソッドの分岐4:
//   recaptchaSolved === 1 → score -= DECREASE_SCORE, return
// 減算後に負の値になる場合は、スコアは 0 にクランプされる（負のスコアは存在しない）。
//
// session 側: score_session=2 < DECREASE_SCORE_SESSION(4)
//             2 - 4 = -2 → max(0) = 0  ← クランプ発生（このテストのキーポイント）
// ip 側:      score_ip=2 >= DECREASE_SCORE_IP(1)
//             2 - 1 = 1                 ← クランプなし（対比確認）
//
// step 1: CLEAR_DB
//   is_ua_mismatch=1 (+2) / over_threshold なし で INSERT
//   → score_session=2, score_ip=2
//   （is_ua_mismatch=1 → isSuspiciousAccess=1 → 減算スキップ → score=2 で確定）
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   is_decreased_*=0（分岐2 をスキップ）
//   is_no_anomaly_*=0（分岐3 をスキップ）
//   recaptcha_solved=1 → 分岐4
//   session: 2 - DECREASE_SCORE_SESSION(4) = -2 → max(0) = 0  ← クランプ
//   ip:      2 - DECREASE_SCORE_IP(1) = 1                      ← クランプなし
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// is_ua_mismatch=1 (+2) / over_threshold なし で score=2 を書き込む
$caseLabel = 'Case<br>recaptcha クランプ（分岐4 floor）, step 1: is_ua_mismatch(+2) で score=2 を INSERT';

$contents = [
    'session_id'       => 'recaptcha_clamp_test_01',
    'ip_address'       => '192.168.25.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 1,   // score +2（session・ip 両方）
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => 0,  // 閾値(60)未満 → isOverThresholdSession=0
    'access_count_ip'       => 0,  // 閾値(600)未満 → isOverThresholdIp=0
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → decreaseScore() 早期リターン → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) = 2
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) = 2
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
$scoreSessionExpected = 2;
$scoreIpExpected      = 2;

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: recaptcha_solved=1 かつ session score(2) < DECREASE_SCORE_SESSION(4) のとき
//         max(0) クランプが発生することを確認する (NOT_CLEAR_DB)
// 同じ session_id / ip_address → 両方 UPDATE
$caseLabel = 'Case<br>recaptcha クランプ（分岐4 floor）, step 2: session(2-4=-2→0クランプ), ip(2-1=1クランプなし)';

$contents = [
    'session_id'       => 'recaptcha_clamp_test_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '192.168.25.1',               // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,  // 疑わしくない
    'is_ua_mismatch'   => 0,  // 疑わしくない
    'recaptcha_solved'  => 1, // ← このテストのキーポイント: 分岐4 を実行する
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 2,  // step 1 で DB に書かれたスコア
    // 2 < DECREASE_SCORE_SESSION(4) → 減算後に負になる → クランプ対象
    'score_ip'              => 2,  // step 1 で DB に書かれたスコア
    // 2 >= DECREASE_SCORE_IP(1)    → 減算後に正になる → クランプ不要
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 0,  // 分岐2 をスキップするため 0
    'is_decreased_ip'       => 0,  // 同上
    'is_no_anomaly_session' => 0,  // 分岐3 をスキップするため 0
    'is_no_anomaly_ip'      => 0,  // 同上 → 分岐4（recaptcha_solved）へ進む
];

// スコア計算:
// session: previous(2) + 加算なし = 2
//          isSuspiciousAccess=0（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_SESSION(4) → 2 - 4 = -2 → max(0) = 0
//          → score_session = 0  ← クランプ発生（このテストのキーポイント）
//
// ip:      previous(2) + 加算なし = 2
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_IP(1) → 2 - 1 = 1
//          → score_ip = 1  ← クランプなし（session との対比確認）
$scoreSessionExpected = 0;  // 2 - DECREASE_SCORE_SESSION(4) = -2 → max(0) = 0（クランプ）
$scoreIpExpected      = 1;  // 2 - DECREASE_SCORE_IP(1) = 1（クランプなし）

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: recaptcha クランプ テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);

// -------------------------------------------------------
// recaptcha_solved === 1 かつ ip score = 0 のとき
// 減算結果が負になるため max(0) でクランプされることを確認する
//
// [テストの意図]
// 前のクランプテストは session 側のクランプ（2 - 4 = -2 → 0）を確認した。
// このテストは ip 側のクランプを確認する。
// DECREASE_SCORE_IP = 1 なので、score_ip = 0 のとき 0 - 1 = -1 → max(0) = 0 となる。
//
// session 側: score_session = 5（高い値）、recaptcha_solved=1 → 5 - 4 = 1（クランプなし）
//             ← session クランプなしを対比確認として使用
// ip  側: score_ip = 0、recaptcha_solved=1 → 0 - 1 = -1 → max(0) = 0
//             ← ip クランプ発生（このテストのキーポイント）
//
// [step1 の score 設定]
// session: score = 5を目指す。ua_mismatch(+2) + over_threshold_session(+3) = 5。
// ip:      score = 0 を目指す。新規 IP と見なして DB に記録なし。
//          session が INSERT されるとき、ip も同時に INSERT されるので、
//          step1 で ip スコア 0 をセットして INSERT する。
//
// step 1: CLEAR_DB
//   is_ua_mismatch=1(+2) + access_count_session=閾値(+3) で INSERT
//   score_session=5
//   access_count_ip=0 → isOverThresholdIp=0 → score_ip=0+2=2（is_ua_mismatch のは session・ip 共通）
//
// 注意: is_ua_mismatch は session・ip 両方に +2 するため、
//   step1 の ip score は 0 でなく 2 になる。
//   ip score = 0 は、step2 で mock に 0 をセットすることで模倣する。
//
// step 2: NOT_CLEAR_DB（同じ session_id / ip_address → 両方 UPDATE）
//   疑わしくないアクセス（is_no_ua=0, is_ua_mismatch=0, access_count < 閾値）
//   is_decreased=0, is_no_anomaly=0
//   recaptcha_solved=1 → 分岐4
//   mock に score_session=5, score_ip=0 をセットする（「DB に 0 が記録されている」状況を模倣）
//   session: 5 - DECREASE_SCORE_SESSION(4) = 1（クランプなし、対比確認）
//   ip:      0 - DECREASE_SCORE_IP(1) = -1 → max(0) = 0（クランプ発生！）
//
// step 3: record count が 2（INSERT でなく UPDATE）であることを確認する
// -------------------------------------------------------

// step 1: insert (CLEAR_DB)
// is_ua_mismatch=1(+2) + over_threshold_session(+3) で session score=5 を書き込む
// ip score は is_ua_mismatchの +2 が共通で適用されるし、step2 で mock に 0 をセットする
$caseLabel = 'Case<br>recaptcha ip クランプ（分岐4 floor）, step 1: ua_mismatch+over_threshold_session で INSERT';

$contents = [
    'session_id'       => 'recaptcha_ip_clamp_01',
    'ip_address'       => '192.168.26.1',
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,
    'is_ua_mismatch'   => 1,   // session・ip 両方 +2
    'recaptcha_solved'  => 0,
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 0,
    'score_ip'              => 0,
    'access_count_session'  => JUST_THRESHOLD_SESSION,  // 閾値(60) → isOverThresholdSession=1 → session +3
    'access_count_ip'       => 0,                       // 閾値(600)未満 → isOverThresholdIp=0
    'is_decreased_session'  => 0,
    'is_decreased_ip'       => 0,
    'is_no_anomaly_session' => 0,  // is_ua_mismatch=1 → isSuspiciousAccess=1 → 減算スキップ
    'is_no_anomaly_ip'      => 0,  // 同上
];

// スコア計算:
// session: previous(0) + ua_mismatch(+2) + over_threshold_session(+3) = 5
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
// ip:      previous(0) + ua_mismatch(+2) + over_threshold_ip(0) = 2
//          isSuspiciousAccess=1 → decreaseScore() 分岐1: 早期リターン → 減算なし
//          (この step1 の ip スコア=2 は step2 の mock で上書きし、実際には 0 の状態から開始する)
$scoreSessionExpected = 5;
$scoreIpExpected      = 2;  // step2 で mock に 0 をセットするため、ここでは 2 が展示される

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    CLEAR_DB
);

// step 2: score_ip=0 の状態から recaptcha_solved=1 で ip クランプが発生することを確認する (NOT_CLEAR_DB)
// mock の score_ip に 0 をセットすることで、
// 「 DB に ip score 0 が記録されている状態からアクセスした 」状況を模倣する
$caseLabel = 'Case<br>recaptcha ip クランプ（分岐4 floor）, step 2: score_ip=0, recaptcha=1 → 0-1=-1 → max(0)=0';

$contents = [
    'session_id'       => 'recaptcha_ip_clamp_01',  // step 1 と同じ → session UPDATE
    'ip_address'       => '192.168.26.1',             // step 1 と同じ → ip UPDATE
    'simple_ua'        => 'Chrome/91',
    'is_no_ua'         => 0,  // 疑わしくない
    'is_ua_mismatch'   => 0,  // 疑わしくない
    'recaptcha_solved'  => 1, // ← このテストのキーポイント: 分岐4 を実行する
    'user_agent'       => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
];

$uaData = [
    'score_session'         => 5,  // step 1 で DB に書かれたスコア
    'score_ip'              => 0,  // ← このテストのキーポイント
    // 0 を mock にセットすることで
    // 「DB に ip score 0 が記録されている」状況を模倣
    // 0 - DECREASE_SCORE_IP(1) = -1 → max(0) = 0 が発生する
    'access_count_session'  => 1,  // 閾値(60)未満 → isOverThresholdSession=0 → 疑わしくない
    'access_count_ip'       => 1,  // 閾値(600)未満 → isOverThresholdIp=0 → 疑わしくない
    'is_decreased_session'  => 0,  // 分岐2 をスキップするため 0
    'is_decreased_ip'       => 0,  // 同上
    'is_no_anomaly_session' => 0,  // 分岐3 をスキップするため 0
    'is_no_anomaly_ip'      => 0,  // 同上 → 分岐4（recaptcha_solved）へ進む
];

// スコア計算:
// session: previous(5) + 加算なし = 5
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_session=0 → 分岐2 スキップ
//          is_no_anomaly_session=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_SESSION(4) → 5 - 4 = 1
//          → score_session = 1（クランプなし、対比確認）
//
// ip:      previous(0) + 加算なし = 0
//          isSuspiciousAccess=0
//          → decreaseScore() を呼び出す
//          is_decreased_ip=0 → 分岐2 スキップ
//          is_no_anomaly_ip=0 → 分岐3 スキップ
//          recaptcha_solved=1 → 分岐4: score -= DECREASE_SCORE_IP(1) → 0 - 1 = -1 → max(0) = 0
//          → score_ip = 0  ← ip クランプ発生（このテストのキーポイント）
$scoreSessionExpected = 1;  // 5 - DECREASE_SCORE_SESSION(4) = 1（クランプなし、対比）
$scoreIpExpected      = 0;  // 0 - DECREASE_SCORE_IP(1) = -1 → max(0) = 0（ip クランプ）

runTestWriteUaScores(
    $caseLabel,
    $contents,
    $uaData,
    $scoreSessionExpected,
    $scoreIpExpected,
    $pdo,
    NOT_CLEAR_DB
);  // クリアしない → 両方 UPDATE になることを確認

// step 3: record count が 2 であることを確認する（INSERT でなく UPDATE）
$caseLabel = 'Record count = 2: recaptcha ip クランプ テスト（session・ip とも UPDATE）';
$expectedCount = 2;
checkRecordCount($caseLabel, $pdo, $expectedCount);


//  データベース接続を閉じます。    
$dbManager->disconnect();
echo "Result: {$totalPass} passed, {$totalFail} failed.<br><br>";
