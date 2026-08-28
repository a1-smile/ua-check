<?php
// 同じ階層にある .env ファイルを読み込む
require_once __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad(); // .env がなくても落ちない

//  index.php などの
//  エントリポイントで
//  このファイルを読み込むことで、
//  環境変数を利用可能にする

//  require_once __DIR__ . '/../env.php'; // 必要に応じて環境変数を読み込む