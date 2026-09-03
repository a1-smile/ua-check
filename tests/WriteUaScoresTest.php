<?php

//  PHPUnit\Framework\TestCase
//  というクラス名を TestCase として
//  使うための宣言です。
//  以下 TestCase と書かれた部分は 
//  PHPUnit\Framework\TestCase を指します。
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/common/dbmanager.php';
require_once __DIR__ . '/../src/interface_request_content.php';
require_once __DIR__ . '/../src/request_content_implementation.php';
require_once __DIR__ . '/../src/mock_request_content.php';
require_once __DIR__ . '/../src/interface_ua_repository.php';
require_once __DIR__ . '/../src/mock_ua_repository.php';
require_once __DIR__ . '/../src/risk_evaluation_result.php';
require_once __DIR__ . '/../src/user_agent_risk_evaluator.php';
require_once __DIR__ . '/../src/write-ua.php';

//  final はクラスが継承されないことを示すキーワードです。
final class WriteUaScoresTest extends TestCase
{
    private DBManager $dbManager;
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->dbManager = new DBManager();
        $this->dbManager->connect();
        $this->pdo = $this->dbManager->get_db();

        $this->pdo->exec('TRUNCATE TABLE ua_scores');
    }

    protected function tearDown(): void
    {
        $this->dbManager->disconnect();
    }

    public function testWritesScoresWhenUserAgentIsMissing(): void
    {
        //  サーバーからのリクエスト内容を模擬する配列
        $contents = [
            'session_id' => 'abc123',
            'ip_address' => '192.168.0.1',
            'simple_ua' => 'Chrome/91',
            'is_no_ua' => 1,
            'is_ua_mismatch' => 0,
            'recaptcha_solved' => 0,
            'user_agent' => 'Mozilla/5.0',
        ];
        //  UA リポジトリ（DB）から取得されるデータを模擬する配列
        $uaData = [
            'score_session' => 0,
            'score_ip' => 0,
            'access_count_session' => 0,
            'access_count_ip' => 0,
            'is_decreased_session' => 0,
            'is_decreased_ip' => 0,
            'is_no_anomaly_session' => 0,
            'is_no_anomaly_ip' => 0,
        ];
        //  モックオブジェクト（インスタンス）を作成して依存関係を注入する
        $requestContent = new MockRequestContent1($contents);
        $uaRepository = new MockUaRepository($uaData);
        $riskEvaluator = new UserAgentRiskEvaluator(
            $requestContent,
            $uaRepository
        );

        $writeUa = new WriteUa(
            $this->pdo,
            $requestContent,
            $uaRepository,
            $riskEvaluator
        );

        //  実際に UA スコアをDBに書き込む処理を実行する
        $writeUa->writeUaScores();

        //  DB に書き込まれた内容を検証する
        //  SQL文を準備する
        $statement = $this->pdo->prepare(
            'SELECT subject_key, subject_type, score
             FROM ua_scores
             WHERE subject_key = :subjectKey'
        );
        //  session_id に対応するレコードを取得する
        $statement->execute(['subjectKey' => 'abc123']);
        $sessionRow = $statement->fetch(PDO::FETCH_ASSOC);

        //  取得したレコードの内容を確認する
        //  record があるかを確認する
        $this->assertNotFalse($sessionRow);
        //  subject_key が一致するかを確認する
        $this->assertSame('abc123', $sessionRow['subject_key']);
        //  subject_type が一致するかを確認する
        $this->assertSame('session', $sessionRow['subject_type']);
        //  score が期待通りかを確認する
        $this->assertSame(1, (int) $sessionRow['score']);
        //  IP アドレスに対応するレコードを取得する
        $statement->execute(['subjectKey' => '192.168.0.1']);
        $ipRow = $statement->fetch(PDO::FETCH_ASSOC);

        $this->assertNotFalse($ipRow);
        $this->assertSame('192.168.0.1', $ipRow['subject_key']);
        $this->assertSame('ip', $ipRow['subject_type']);
        $this->assertSame(1, (int) $ipRow['score']);

        //  ua_scores テーブルのレコード数を取得する
        $count = (int) $this->pdo
            ->query('SELECT COUNT(*) FROM ua_scores')
            //  カウント数が格納される。
            ->fetchColumn();
        //  一行目の一列目を取り出す。
        //  期待されるレコード数と比較する
        $this->assertSame(2, $count);
    }
}
