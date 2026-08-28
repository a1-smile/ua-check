<?php

interface UaRepository
{
    
    //  追跡対象に対するスコアを返す getter
    public function getScoreSession(): int;
    public function getScoreIp(): int;

    //  data base から score を取得する
    //  実装で記述
    //public function fetchScore(string $subjectKey, string $subjectType): array;
    

    // アクセス回数を返す getter
    public function getAccessCountSession(): int;
    public function getAccessCountIp(): int;

    //  data base からアクセス回数を配列で取得する
    //  実装で記述
    // public function fetchAccessCountArray(string $sessionId, string $ipAddress): array;
    //  配列からアクセス回数を取得する
    //  実装で記述
    // public function plunkAccessCountSession(array $accessCountArray): int;
    // public function plunkAccessCountIp(array $accessCountArray): int;


    // スコアが減少したかどうかを返す getter（1/0想定）
    public function getIsDecreasedSession(): int;
    public function getIsDecreasedIp(): int;
    
    // data base でスコアが減少したかどうかを確認する
    //  実装で記述
    // public function checkIsDecreasedLast30Minutes(string $subjectType, string $subjectKey): int;


    // 追跡対象に異常がない場合は 1 を返す getter
    public function getIsNoAnomalySession(): int;
    public function getIsNoAnomalyIp(): int;

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