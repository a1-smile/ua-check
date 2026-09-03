# DB をテスト用に設定する

```sql
CREATE DATABASE IF NOT EXISTS test_student
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'ua_check_test'@'localhost'
  IDENTIFIED BY 'test_only_password';

GRANT ALL PRIVILEGES ON test_student.* TO 'ua_check_test'@'localhost';

FLUSH PRIVILEGES;
```

# 確認
```sql
SHOW DATABASES LIKE 'test_student';
SHOW GRANTS FOR 'ua_check_test'@'localhost';
```

# table 作成

```sql
CREATE TABLE test_student.ua_scores LIKE school.ua_scores;  
```

# 接続先を変更する
```php
<?php
$this->access_info = 'mysql:host=localhost;dbname=test_student;charset=utf8mb4';
$this->user = 'ua_check_test';
$this->password = 'test_only_password';
```

としました。

tests\test-write-ua-score.php

のようなテストコードは、
PHPUnit を使って実装することにてきしていますか？

はい、test-write-ua-score.php の目的は PHPUnit に適しています。
WriteUaのメソッドwriteUaScores() が実際に
ua_scores テーブルへ正しい 
session/IP レコードを書き込むかを検証しているため、
これは PHPUnit で管理しやすい結合テストです。

ただし、
現在のファイルは
「PHP スクリプトとして直接実行するテスト」なので、
そのまま PHPUnit に読み込ませる形式には適していません。
PHPUnit 用には次を変える必要があります。

echo と die() を、
$this->assertSame() / $this->assertNotFalse() 
などのアサーションへ置換する
global $totalPass, $totalFail を削除する
DB 接続と TRUNCATE を setUp() に置く
接続解除を tearDown() に置く
各ケースを public function test...(): void のメソッドにする
ファイル名を WriteUaScoresTest.php のように Test.php で終える
テスト対象の例外は die() で止めず、PHPUnit に失敗として報告させる
たとえば、現在の最初のケースは次のような形になります。


```php
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

        //  SQL文を準備する
        $statement = $this->pdo->prepare(
            'SELECT subject_key, subject_type, score
             FROM ua_scores
             WHERE subject_key = :subjectKey'
        );
        //  session_id に対応するレコードを取得する
        $statement->execute(['subjectKey' => 'abc123']);
        $sessionRow = $statement->fetch(PDO::FETCH_ASSOC);

        $this->assertNotFalse($sessionRow);
        $this->assertSame('abc123', $sessionRow['subject_key']);
        $this->assertSame('session', $sessionRow['subject_type']);
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

重要なのは、dbmanager.php の接続先を常に
test_student に固定しないことです。
アプリケーション本体が誤ってテスト DB を
使ってしまいます。
PHPUnit 用の専用 TestDatabaseManager を作るか、
環境変数 DB_NAME=test_student を PHPUnit 実行時だけ渡す構成が安全です。

また、メモ内の SQL コードブロックは閉じ忘れがあります。MySQL に投入する SQL はコメントを外して、次のように分けると安全です。

```
CREATE DATABASE IF NOT EXISTS test_student
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'ua_check_test'@'localhost'
  IDENTIFIED BY 'test_only_password';

GRANT ALL PRIVILEGES ON test_student.* TO 'ua_check_test'@'localhost';

FLUSH PRIVILEGES;

CREATE TABLE test_student.ua_scores LIKE school.ua_scores;
```

重要なのは、dbmanager.php の接続先を常に
 test_student に固定しないことです。
 アプリケーション本体が誤ってテスト DB を使ってしまいます。
 PHPUnit 用の専用 TestDatabaseManager を作るか、
 環境変数 DB_NAME=test_student を PHPUnit 実行時だけ渡す構成が安全です。

ということは、本番環境とテスト環境で接続先を切り替える仕組みが必要です。
テスト時には、.env ファイルの環境変数を書き換える。という理解であっていますか？


# 環境変数の設定
ua-check dir 直下に 
.gitignore ファイル を作成
```
.env
```
と記述する。

ua-check dir 直下に 
.env ファイルを作成し、次の内容を記述します。

```
DB_HOST=localhost
DB_NAME=test_student
DB_USER=ua_check_test
DB_PASSWORD=test_only_password
```

PHP では、DBManeger class で環境変数から接続情報を取得するようにします。
```
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

$dbHost = $_ENV['DB_HOST'];
$dbName = $_ENV['DB_NAME'];
$dbUser = $_ENV['DB_USER'];
$dbPassword = $_ENV['DB_PASSWORD'];

$pdo = new PDO(
    "mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4",
    $dbUser,
    $dbPassword
);
```

サンプルとして、.env.example ファイルを作成し、次の内容を記述します。

```
DB_HOST     =localhost or 127.0.0.1 or DB接続情報を確認
DB_NAME     =your_database_name
DB_USER     =your_database_user
DB_PASSWORD =
```
こちらは、git 管理対象に含めます。

gitignore も コミットする。

# dotenv の使用
dotenv をインストールしまして、
環境変数を読み込むことを確認しました。

phpunit.xml で環境変数を上書きする方法
について初心者に解説おねがいします。

```
<?xml version="1.0" encoding="UTF-8"?>
<phpunit bootstrap="tests/bootstrap.php" colors="true">
  <testsuites>
    <testsuite name="App Test Suite">
      <directory>tests</directory>
    </testsuite>
  </testsuites>

  <php>
    <env name="APP_ENV" value="testing" force="true"/>
    <env name="DB_HOST" value="localhost" force="true"/>
    <env name="DB_NAME" value="test_student" force="true"/>
    <env name="DB_USER" value="ua_check_test" force="true"/>
    <env name="DB_PASSWORD" value="test_only_password" force="true"/>
  </php>
</phpunit>
```

bootstrap.php
```
<?php
require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad(); // .env がなくても落ちない
```

DBManager class では、環境変数から接続情報を取得するようにします。
```
<?php
$dbHost = $_ENV['DB_HOST'] ?? 'localhost';
$dbName = $_ENV['DB_NAME'] ?? 'school';
$dbUser = $_ENV['DB_USER'] ?? 'root';
$dbPass = $_ENV['DB_PASSWORD'] ?? '';

$pdo = new PDO(
    "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
    $dbUser,
    $dbPass
);
```

phpunit.xml と bootstrap.php を
プロジェクトディレクトリのいちばんうえに作成して、
DBManagerを書き換えればよろしいでしょうか？
DBManagerには
Dotenv を使って環境変数を読み込む処理を追加する必要がありますか？

いいえ、
むしろ、env.php や bootstrap.php 
で環境変数を読み込むようにしておけば、
DBManager では特に Dotenv を使う必要はありません。

index.php などのエントリポイントで
```
require_once __DIR__ . '/bootstrap.php';
//または、
//require_once __DIR__ . '/env.php'; // 必要に応じて環境変数を読み込む
require_once __DIR__ . '/dbmanager.php';

# tests/.env から環境変数を読み込むように変更
tests/.env を作成しました。
.gitignore に tests/.env を追加 。

phpunit.xml は bootstrap.php を読み込むように設定しています。
phpunit.xml から環境変数の記述を削除し、bootstrap.php で読み込むように変更しました。

phpunit.xml と、
bootstrap.php と
tests/.env の記述は合っていますか？