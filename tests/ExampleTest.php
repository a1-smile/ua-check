<?php

use PHPUnit\Framework\TestCase;

class ExampleTest extends TestCase
{
    public function testExample(): void
    {
        $this->assertSame(2, 1 + 1);
    }
}
/* 






オファーを受け取る

はい、原因はかなり明確です。
PHP 8.3.1が原因ではありません。

今回のポイントは、実行したコマンドが

composer require --dev phpunit/phpunit:12
のように、12 と指定されていることです。

Composerから見ると 12 は、

「PHPUnit 12.x の最新版」ではなく、12.0.0という特定バージョン

として解釈されます。

そして、エラーメッセージを見ると、

found phpunit/phpunit[12.0.0]
but these were not loaded,
because they are affected by security advisories
となっています。

つまり、

PHPUnit 12.0.0にはセキュリティアドバイザリがあるため、Composer 2.10.2がインストールを拒否した

ということです。

今回はこうしてください
まず、C:\dev\ua-checkに移動します。

cd /d C:\dev\ua-check
そして、

composer require --dev phpunit/phpunit:^12
としてください。

重要なのは、

12
ではなく、

^12
です。

^12 は簡単にいうと、

PHPUnit 12系の中から、条件を満たす新しいバージョンを選んでください

という指定です。

今回のエラーでは、

12.0.0
にセキュリティ問題があるため、12.0.0以外の新しい12系をComposerに選ばせるのが適切です。

もう一つ確認しておきたいこと
先ほどのコマンドが失敗したため、

./composer.json has been created
のあと、

Installation failed, deleting ./composer.json.
となっています。

最後に

deleting ./composer.json
と出ていますので、Composerが作成したcomposer.jsonも削除されています。

したがって、基本的にはそのまま、

cd /d C:\dev\ua-check
composer require --dev phpunit/phpunit:^12
を実行し直して大丈夫です。

成功したら、

vendor\bin\phpunit --version
で確認してください。

例えば、

PHPUnit 12.x.x
と表示されれば成功です。

今回のエラーを整理すると
PHP 8.3.1
     ↓
PHPUnit 12は使用可能
     ↓
「12」と指定
     ↓
Composerが「12.0.0」と解釈
     ↓
PHPUnit 12.0.0にセキュリティアドバイザリあり
     ↓
Composer 2.10.2がインストールを拒否
です。

セキュリティアドバイザリを無視する設定には、今回は変更しないでください。
Composerが安全上の理由で止めてくれているので、まずは^12で新しい12系を取得するのが正しい対応です。

もし^12でもエラーになった場合は、そのエラー全文をそのまま貼ってください。 次にどこを直せばいいか、一つずつ確認できます。




広告

はい、完全に成功しています！ 👍

PHPUnit 12.5.33 by Sebastian Bergmann and contributors.
と表示されているので、

PHP 8.3.1 ✅

Composer 2.10.2 ✅

PHPUnit 12.5.33 ✅

C:\dev\ua-check にインストール ✅

という状態です。

今回の構成は、最終的にこうなっています。

C:\dev\ua-check
│
├─ composer.json
├─ composer.lock
├─ vendor\
│   └─ bin\
│       └─ phpunit
│
└─ （これからPHPの本体・テストコード）
        ↑
        │ シンボリックリンク
        ↓
C:\MAMP\htdocs\ua-check
そして、PHPUnitの実行は今後、

vendor\bin\phpunit
でできます。

次にやること
ここからは、実際にPHPUnitが動くことを確認するために、非常に簡単なテストを1個作って実行してみるのがおすすめです。

例えば、

tests
└── ExampleTest.php
を作って、

<?php

use PHPUnit\Framework\TestCase;

class ExampleTest extends TestCase
{
    public function testExample(): void
    {
        $this->assertSame(2, 1 + 1);
    }
}
として、

vendor\bin\phpunit tests
を実行します。

これで、

OK (1 test, 1 assertion)
のようになれば、PHPUnitのインストールだけでなく、テストの実行環境まで正常に構築できたことになります。

今回のようにPHPUnitのバージョン指定で少しつまずきましたが、12ではなく"^12"と指定するところがポイントでした。
ここまでできていれば、かなり良いところまで環境構築できています。


C:\dev\ua-check>vendor\bin\phpunit tests
PHPUnit 12.5.33 by Sebastian Bergmann and contributors.

Runtime:       PHP 8.3.1

.                                                                   1 / 1 (100%)

Time: 00:00.004, Memory: 14.00 MB

OK (1 test, 1 assertion)
となりました。

はい、正常に動作しています。🎉

今回の結果を見ると、

PHPUnit 12.5.33
Runtime: PHP 8.3.1

.  1 / 1 (100%)

OK (1 test, 1 assertion)
なので、次の3つがすべて確認できました。

PHP 8.3.1でPHPUnit 12.5.33が動いている ✅

tests ディレクトリが正しく認識されている ✅

テスト1件が実行され、1件のアサーションも成功した ✅

特に、

OK (1 test, 1 assertion)
が重要です。

これは、

「テストを1個実行して、その中の検証（assertion）も1個実行し、期待どおりだった」

という意味です。

現在の環境
PHP 8.3.1
   │
   ├── Composer 2.10.2
   │
   └── PHPUnit 12.5.33
           │
           └── tests/ExampleTest.php
そして、

C:\dev\ua-check
        ↑
     実体
        │
        │ シンボリックリンク
        ↓
C:\MAMP\htdocs\ua-check
という構成もそのまま維持できます。

これでPHPUnitの環境構築は完了と考えて大丈夫です。

次の段階では、今回のExampleTestのような単純なテストではなく、実際に作ろうとしている UAチェックのPHPコードを対象にPHPUnitテストを書くところへ進めます。

その際は、いきなり難しいテストを書くより、

「本番コード → テスト対象の関数 → PHPUnitで期待値を検証」

という流れから始めると理解しやすいです。




広告
広告は、ChatGPT からの回答には影響しません。チャットは未公開のままです。 
広告とパーソナライズの詳細を確認する

ありがとうございます。

どういたしまして！
無事に PHP 8.3.1 + Composer 2.10.2 + PHPUnit 12.5.33 の環境が構築できてよかったです。

ここまでの設定で、PHPUnitを使ったテストコードを書き始める準備はできています。👍


メモリを増やして、より関連性の高い回答を得る
アップグレードすると、保存したファイルや過去の会話をもとに、ChatGPT がより詳しい回答を返せるようになります。

Plus を無料で試す




*/