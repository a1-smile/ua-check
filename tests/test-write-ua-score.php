<?php
/*
ua-check/tests/test-write-ua-scores.php
では、
ua-check/src/write-ua.php
に定義されている
class WriteUaのwriteUaScores() メソッドをテストします。
*/

/* テストケース
session insert / ip insert
*/

/* risk score を
計算する仕様を説明します。
テスト用の expected score はこの仕様の
ハードコードによって計算します。
また、
これにより、risk score を計算するロジック
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

//  table ua_scores を TRUNCATE する関数を定義します。
function truncateUaScoresTable(PDO $pdo): void
{
    try {
        $pdo->exec("TRUNCATE TABLE ua_scores");
        echo "Table ua_scores truncated successfully.\n";
    } catch (Exception $e) {
        echo "Error truncating table ua_scores: " . $e->getMessage() . "\n";
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
    echo "<b>{$caseLabel}</b>\n\n";

    if ($clearDb) {
        // table ua_scores をクリア
        truncateUaScoresTable($pdo);
    }  //END IF

    //  サーバーからのリクエスト情報（仮想的なもの）を用いて、モックインスタンスを作成します。
    $mock_request_content = new MockRequestContent1($contents);
    //  次に、DBの情報(仮想的なもの)を提供するためのモックインスタンスを作成します。
    $mock_ua_repository  = new MockUaRepository($uaData);
    //  モックリスク評価を行うためのインスタンスを作成します。
    $risk_evaluator = new UserAgentRiskEvaluator($mock_request_content, $mock_ua_repository);
    //  次に、WriteUa のインスタンスを作成します。
    //  DBへの書き込みを行うためのインスタンスです。
    $write_ua       = new WriteUa($pdo, $mock_request_content, $mock_ua_repository, $risk_evaluator);
    try {
        //  実際に UA スコアを書き込みます。
        $write_ua->writeUaScores();
    } catch (DbWriteException $e) {
        die("  Error writing anomaly events: " . $e->getMessage() . "\n");
    } catch (Exception $e) {
        die("  Unexpected error: " . $e->getMessage() . "\n");
    }  // END try-catch

    // SELECTで session に紐づいた record を取得する。そして期待値と照合する
    $session_id = $mock_request_content->getSessionId();
    try {
        $stmt = $pdo->prepare("SELECT * FROM ua_scores WHERE subject_key = :session_id");
        $stmt->bindParam(':session_id', $session_id, PDO::PARAM_STR);
        $stmt->execute();
        $row  = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        die("  Error querying table: " . $e->getMessage() . "\n");
    }

    if ($row === false) {
        $totalFail++;
        die("  FAIL: No log entry found in ua_scores.\n");
    }
    //  session に紐づいたレコードが存在することを確認しました。次に各フィールドの値をチェックします。
    //  $ok を用いて、テストが一度失敗したら、それ以降のテストも失敗扱いにします。
    //  テストが一度失敗したコードは、信頼性が低いため、それ以降のチェックも失敗扱いにするという方針です。
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
        die("  session checks failed. skipping ip checks.\n");
    }

    // SELECTで ip address に紐づいた record を取得する。そして期待値と照合する
    $ip_address = $mock_request_content->getIpAddress();
    try {
        $stmt = $pdo->prepare("SELECT * FROM ua_scores WHERE subject_key = :ip_address");
        $stmt->bindParam(':ip_address', $ip_address, PDO::PARAM_STR);
        $stmt->execute();
        $row  = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        die("  Error querying table: " . $e->getMessage() . "\n");
    }
    if ($row === false) {
        die("  FAIL: No log entry found in ua_scores.\n");
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
        echo "  All checks passed.\n";
    } else {
        //  test 失敗のため stop します。
        die("Ip test failed. Stopping further tests.\n");
    }
    echo "\n";
}  // END function runTestWriteUaScores()

//  table ua_scores のレコード件数を取得する関数を定義します。
function getRecordCount(PDO $pdo): int
{
    try {
        $stmt = $pdo->query("SELECT COUNT(*) FROM ua_scores");
        return (int)$stmt->fetchColumn();
    } catch (Exception $e) {
        echo "  Error counting records: " . $e->getMessage() . "\n";
        return -1; // エラーの場合は -1 を返す
    }  // END try-catch
}  // END function getRecordCount()

//  record count が期待値と一致するかどうかをチェックする関数を定義します。
function checkRecordCount(
    string $caseLabel,
    PDO $pdo,
    int $expectedCount
): void {
    echo "<b>{$caseLabel}</b>\n";

    global $totalPass, $totalFail;

    $actualCount = getRecordCount($pdo);
    if ($actualCount === -1) {
        $totalFail++;
        die("  FAIL: Could not retrieve record count.<br><br>");
    }

    if ($actualCount === $expectedCount) {
        $totalPass++;
        echo "  PASS: Record count is as expected. Count: {$actualCount}\n";
    } else {
        $totalFail++;
        die("  FAIL: Record count is not as expected. Expected: {$expectedCount}, Actual: {$actualCount}\n");
    }
} // END function checkRecordCount()

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

const CLEAR_DB = true; // テスト開始前にDBをクリアするかどうか。true にすると、テスト開始前に table ua_scores を TRUNCATE します。
const NOT_CLEAR_DB = false; // テスト開始前にDBをクリアしない場合。テストケースによっては、前のテストケースのデータが残っていることを前提とするものもあるため、こちらの定数も定義しておきます。

//  DBManager クラスを使用するために、require_once します。
require_once __DIR__ . '/../src/common/dbmanager.php';
//  DBManager を new します。
$dbManager = new DBManager();
//  データベースに接続します。
try {
    $dbManager->connect();
    echo "Database connection successful.\n";
} catch (Exception $e) {
    echo "Database connection failed: " . $e->getMessage() . "\n";
    exit(1);
}
//  PDO インスタンスを取得します。
$pdo = $dbManager->get_db();

//  RequestContent インターフェイスを、require_once します。
require_once __DIR__ . '/../src/interface_request_content.php';

//  RequestContentImplementation クラスを、require_once します。
//  mock_request_content.php 内で、simple ua を求めるときに 
//  RequestContentImplementation の静的メソッドを使用するためです。
require_once __DIR__ . '/../src/request_content_implementation.php';

//  その他のテストに必要なファイルも require_once します。
require_once __DIR__ . '/../src/mock_request_content.php';
require_once __DIR__ . '/../src/interface_ua_repository.php';
require_once __DIR__ . '/../src/mock_ua_repository.php';
require_once __DIR__ . '/../src/risk_evaluation_result.php';
require_once __DIR__ . '/../src/user_agent_risk_evaluator.php';
require_once __DIR__ . '/../src/write-ua.php';
require_once __DIR__ . '/../src/exceptions.php';
require_once __DIR__ . '/../src/function-check.php';

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

/* 'is_no_anomaly_ip' */
$uaData = [
    'score_session' => 0,
    'score_ip' => 0,
    'access_count_session' => 0, // 閾値 60
    'access_count_ip' => 0, // 閾値 600
    'is_decreased_session' => 0, // 過去一定期間にスコアが減算されたかどうか
    'is_decreased_ip' => 0, // 過去一定期間にスコアが減算されたかどうか
    'is_no_anomaly_session' => 0, // 'is_no_ua' => 1 と設定してあり、異常があるアクセスなので、こちらの値はスコアに影響しません。
    'is_no_anomaly_ip' => 0       // 異常があるアクセスなので、こちらの値はスコアに影響しません。
];

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

//  データベース接続を閉じます。    
$dbManager->disconnect();
echo "Result: {$totalPass} passed, {$totalFail} failed.\n";
