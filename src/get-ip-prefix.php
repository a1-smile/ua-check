<?php
/**
 * IPアドレスからセッションハイジャック対策用のプレフィックスを取得する
 *
 * @param int $ipv4_blocks IPv4の場合に何ブロックまで取るか（1-4）
 * @param int $ipv6_blocks IPv6の場合に何ブロックまで取るか（1-8）
 * @return string プレフィックス文字列
 * @throws RuntimeException IPアドレスが取得できない場合
 * @throws InvalidArgumentException 無効なIPアドレス形式の場合
 */
function get_ip_prefix_for_session(int $ipv4_blocks = 2, int $ipv6_blocks = 3): string {
    // 1. $_SERVER['REMOTE_ADDR']からIPを取得
    if (!isset($_SERVER['REMOTE_ADDR']) || empty($_SERVER['REMOTE_ADDR'])) {
        throw new RuntimeException('IPアドレスが取得できません');
    }
    
    $ip = $_SERVER['REMOTE_ADDR'];
    
    // IPv4-mapped IPv6アドレスの処理（例: ::ffff:192.0.2.128）
    if (strpos($ip, '::ffff:') !== false) {
        // 最後の':'以降を取り出してIPv4として扱う
        $v4 = substr($ip, strrpos($ip, ':') + 1);
        if (filter_var($v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = $v4;
        }
    }
    
    // 2. IPv4の場合の処理
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        // '.'で区切られたIPを配列に変換
        $parts = explode('.', $ip);
        // $takeを$ipv4_blocks、配列の要素数のどちらか小さい値に設定
        $take = min($ipv4_blocks, count($parts));
        $take = max(1, $take); // 最低1ブロックは取る
        
        return implode('.', array_slice($parts, 0, $take));
    }
    
    // IPv6の場合の処理
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // ':'で区切られたIPを配列に変換
        $parts = explode(':', $ip);
        // 空の要素を除去（::の部分対応）
        $trimmed_parts = array_filter($parts, fn($p) => $p !== '');
        // 配列のインデックスを振り直す
        $parts_filtered = array_values($trimmed_parts);
        //$parts_filtered = array_values(array_filter($parts, fn($p) => $p !== ''));
        // $takeを$ipv6_blocks、配列の要素数のどちらか小さい値に設定
        $take = min($ipv6_blocks, count($parts_filtered));
        $take = max(1, $take); // 最低1ブロックは取る
        
        return implode(':', array_slice($parts_filtered, 0, $take));
    }
    
    // IPv4でもIPv6でもない場合は例外を投げる
    throw new InvalidArgumentException('無効なIPアドレスです: ' . $ip);
}

// 使用例
// try {
//     $prefix = get_ip_prefix_for_session(2, 3);
//     echo "IP Prefix: " . $prefix . "\n";
// } catch (InvalidArgumentException $e) {
//     // データの問題
//     error_log("Invalid data: " . $e->getMessage());
// 
// } catch (RuntimeException $e) {
//     // 環境の問題
//     error_log("Runtime error: " . $e->getMessage());
// }

