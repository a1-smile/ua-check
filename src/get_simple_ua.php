<?php
/**
 * 簡易的なユーザーエージェント情報を取得する関数
 *
 * @param string $ua ユーザーエージェント文字列
 * @return string 簡易的なブラウザ名とバージョン（例: "Chrome/89"）
 */
function get_simple_ua(string $ua): string {
    $ua = trim($ua);
    if ($ua === '') return '';

    // Edge (Chromium) と旧Edge
    if (preg_match('/\bEdg\/(\d+)/i', $ua, $m)) {
        return 'Edge/' . $m[1];
    }
    if (preg_match('/\bEdge\/(\d+)/i', $ua, $m)) {
        return 'Edge/' . $m[1];
    }

    // 主要外（例：Opera, SamsungBrowser）
    if (preg_match('/\bOPR\/(\d+)/i', $ua, $m)) {
        return 'Opera/' . $m[1];
    }
    if (preg_match('/\bSamsungBrowser\/(\d+)/i', $ua, $m)) {
        return 'SamsungBrowser/' . $m[1];
    }

    // Chrome（デスクトップ/Android）と iOS Chrome（CriOS）
    if (preg_match('/\bChrome\/(\d+)/i', $ua, $m)) {
        return 'Chrome/' . $m[1];
    }
    if (preg_match('/\bCriOS\/(\d+)/i', $ua, $m)) {
        return 'Chrome/' . $m[1];
    }

    // Firefox（デスクトップ）と iOS Firefox（FxiOS）
    if (preg_match('/\bFirefox\/(\d+)/i', $ua, $m)) {
        return 'Firefox/' . $m[1];
    }
    if (preg_match('/\bFxiOS\/(\d+)/i', $ua, $m)) {
        return 'Firefox/' . $m[1];
    }

    // Safari は Version/ をブラウザバージョンとして採用
    if (preg_match('/\bVersion\/(\d+)/i', $ua, $m) && preg_match('/\bSafari\/\d+/i', $ua)) {
        return 'Safari/' . $m[1];
    }

    // IE（旧MSIE と IE11）
    if (preg_match('/\bMSIE\s(\d+)/i', $ua, $m)) {
        return 'IE/' . $m[1];
    }
    if (stripos($ua, 'Trident/') !== false && preg_match('/\brv:(\d+)/i', $ua, $m)) {
        return 'IE/' . $m[1];
    }


    return 'Unknown';
}