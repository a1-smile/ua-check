<?php

/**
 * server や session から
 * ユーザーエージェントや IP アドレスなどの
 * 情報を取得するためのインターフェース
 */


// 「UserAgentRiskEvaluator 向けに提供するフラグ
// （UA なし／UA 不一致／reCAPTCHA 成功）を返すインターフェイス」
// と一文を入れておくと、
// 「なぜこの3つだけがインターフェイスに出ているのか」
// が将来の自分にも分かりやすくなります。


interface RequestContent
{
	// session ID を返す getter
	
	public function getSessionId(): string;


	//  session id をserver から取得するメソッド
	//  実装で記述 
	// public function fetchSessionId(): string;

	// IP アドレスを返す getter
	
    public function getIpAddress(): string;
	// IP アドレスを server から取得するメソッド
	//  実装で記述 
	// public function fetchIpAddress(): string;

	// simplified ユーザーエージェントを返す getter
	//  実装で記述 
	// public function getCurrentSimpleUa(): string;

	// 初期の simplified ユーザーエージェントを 
	// server から取得するメソッド
	//  実装で記述 
	// public function fetchInitialSimpleUa(): string;

	// UA を取得するメソッド
	//  実装で記述
	// public function fetchUa(): string;
	// simplified UA を UA から生成するメソッド
	//  実装で記述
	// public function makeSimpleUaFromUa(): string;



	/**
	 * ユーザーエージェントがない場合は 1 を返す
	 * それ以外の場合は 0 を返すことを想定
	 */
	// getter
	public function getIsNoUa(): int;
	// ユーザーエージェントがsetされていない場合は 1 を返す
	// それ以外の場合は 0 を返すことを想定
	// check メソッド
	//  実装で記述 
	// public function checkIsNoUa(): int;

	/**
	 * ユーザーエージェントが
	 * 初回、もしくは前回のアクセスと異なる場合は 1 を返す
	 * それ以外の場合は 0 を返すことを想定
	 */
	// getter
	public function getIsUaMismatch(): int;
	// check メソッド
	//  実装で記述 
	// public function checkIsUaMismatch(): int;
	/**
	 * reCAPTCHA を通過し、かつ
	 * IP アドレスと session id が変化していない場合は 1 を返す
	 * それ以外の場合は 0 を返すことを想定
	 */
	// getter
	public function getRecaptchaSolved(): int;
	// check メソッド
	//  実装で記述 
	// public function checkRecaptchaSolved(): int;
}
