<?php

//  Composer がインストールしたクラスを
//  使えるようにする記述
require_once __DIR__ . '/vendor/autoload.php';

//  Dotenv\Dotenv は Dotenv という名前空間
//  にある Dotenv というクラスという意味。
use Dotenv\Dotenv;
use Dotenv\Exception\InvalidFileException;
use Dotenv\Exception\InvalidPathException;
use Dotenv\Exception\ValidationException;

$dotenv = Dotenv::createImmutable(__DIR__);
try {
    $dotenv->load();
} catch (InvalidPathException $e) {
    exit('.env ファイルが見つかりません');
} catch (InvalidFileException $e) {
    exit('.env ファイルの形式が正しくありません。');
}

//  必須の設定値を確認する場合は、以下のように記述します。
try {
    $dotenv->required([
        'DB_HOST',
        'DB_NAME',
        'DB_USER',
        'DB_PASSWORD',
    ])->notEmpty();
} catch (ValidationException $e) {
    error_log($e->getMessage());
    exit('必須の環境変数が設定されていません: ');
}

echo $_ENV['DB_HOST'] . "\n";
