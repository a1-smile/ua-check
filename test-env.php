<?php

//  Composer がインストールしたクラスを
//  使えるようにする記述
require 'vendor/autoload.php';

//  Dotenv\Dotenv は Dotenv という名前空間
//  にある Dotenv というクラスという意味。
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
try {
    $dotenv->load();
} catch (Dotenv\Exception\InvalidPathException $e) {
exit('.env ファイルが見つかりません')
} catch (Dotenv\Exception\InvalidFileException $e) {
    exit('.env ファイルの形式が正しくありません。');
}

echo $_ENV['DB_HOST']. "\n";