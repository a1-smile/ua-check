<?php
//  dbmanager.php は DBManager クラスを定義するファイルです。

class DBManager
{
    //  プロパティーの定義
    //  データベースアクセス情報
    private $access_info;
    //  データベースのユーザー名
    private $user;
    //  データベースのパスワード
    private $password;
    //  PDO インスタンス
    private $db = null;
    public function get_db()
    {
        return $this->db;
    }
    //  コンストラクタ
    public function __construct()
    {
        $this->access_info = 'mysql:host=localhost;dbname=test_student;charset=utf8mb4';
        $this->user = 'ua_check_test';
        $this->password = 'test_only_password';
    }
    //  データベースに接続するメソッド
    public function connect()
    {
        try {
            $this->db = new PDO($this->access_info, $this->user, $this->password);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {

            //  例外をスローして、呼び出し元で処理できるようにする
            throw $e;
            //             `connect()`メソッド内で`throw $e;`が実行されると、
            // **呼び出し元（たとえば`get_allstudents()`など）
            // のtry-catch構文のcatchブロックに制御が移ります**。

            // ### 具体例

            // ```php
            // public function get_allstudents() {
            //     try {
            //         $this->connect(); // ここで例外が発生するとcatchにジャンプ
            //         // ...以降の処理...
            //     } catch (PDOException $e) {
            //         $this->disconnect();
            //         return null;
            //     }
            // }
            // ```

            // #### 流れ

            // 1. `connect()`で例外（PDOException）が発生し、`throw $e;`が実行される
            // 2. `connect()`の呼び出し元（ここでは`get_allstudents()`）
            // のtryブロックの処理が中断され、catchブロックにジャンプ
            // 3. catchブロック内の処理（例：`$this->disconnect(); return null;`）
            // が実行される

            // ---

            // ### ポイント

            // - `throw`された例外は**呼び出し元のcatchで受け取ることができる**
            // - 例外発生後は、tryブロック内の残りの処理は実行されない
            // - catchブロックでエラー処理や後始末を行うことができる

            // ---

            // **まとめ:**  
            // `connect()`で`throw $e;`が実行されると、呼び出し元のcatchブロックで例外処理が行われます。 
        }
    }
    //  データベースに接続しているか確認するメソッド
    public function is_connected()
    {
        //  $this->db が null でない場合は、接続されていると判断
        return $this->db !== null;  //  $this->db が null でない場合は true を返す
    }
    //  データベースから切断するメソッド
    public function disconnect()
    {
        $this->db = null;
    }
    //  データベースに保存されたすべての学生情報を取得するメソッド
    public function get_allstudents()
    {
        try {
            $this->connect();
            $stmt = $this->db->prepare("SELECT * FROM student ORDER BY id");
            $res = $stmt->execute();
            //  execute() の結果が false の場合は、例外をスローする設定になっているため、
            //  ここで例外が発生します。

            $member = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $this->disconnect();
            return $member;
        } catch (PDOException $e) {
            $this->disconnect();
            return null;
        }
        // 何らかの理由でエラーが起こっても
        // 例外が発生しない場合は、
        // ここで切断して false を返すようにします。
        // データベースから切断して false を返す
        $this->disconnect();
        return false; // 何らかの理由でエラーが起こった場合は null を返す
    }

    //  id カラムが $id の学生情報を取得するメソッド
    public function get_student($id)
    {
        try {
            //  入力値検証
            if (!is_numeric($id) || $id <= 0) {
                throw new InvalidArgumentException('不正な学生IDです: ' . $id);
            }
            //  データベースに接続
            $this->connect();
            //  エラーの場合は例外をなげる設定になっている。
            //  SQL 文を準備
            $sql = 'SELECT * FROM student WHERE id = :id';
            $stmt = $this->db->prepare($sql);
            if ($stmt === false) {
                throw new RuntimeException('SQL文の準備に失敗しました');
            }
            //  プレースホルダーに値をバインド
            $bind_result = $stmt->bindValue(':id', $id, PDO::PARAM_INT);
            if ($bind_result === false) {
                throw new RuntimeException('パラメーターのバインドに失敗しました');
            }

            //  SQL 文を実行
            // SQL文を実行
            $res = $stmt->execute();
            if ($res === false) {
                $error_info = $stmt->errorInfo();
                throw new PDOException(
                    'SQL実行エラー: ' . $error_info[2],
                    $error_info[1]
                );
            }

            //  execute() の戻り値は、
            //  成功した場合は true、失敗した場合は false です。

            //  $member 変数に結果を格納
            $member = $stmt->fetch(PDO::FETCH_ASSOC);
            //  データベースから切断
            $this->disconnect();
            //  レコードが見つからない場合の処理fetch() は false を返すので、
            //  その場合は null を返すようにします。
            //  レコードが見つからない場合は、null を返す
            if ($member === false) {
                return null; // レコードが見つからない場合は null を返す
            }
            //  レコードが見つかった場合は、$member を連想配列の形でを返す
            return $member;
        } catch (PDOException $e) {
            // 詳細なエラー情報をログに記録
            $error_details = [
                'method' => 'get_student',
                'id' => $id,
                'sqlstate' => $e->getCode(), // SQLSTATEエラーコードを取得(PDOのとき)
                'driver_code' => $e->errorInfo[1] ?? null,  // ドライバーエラーコードを取得
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ];
            error_log('DBManager PDOException: ' . json_encode($error_details, JSON_UNESCAPED_UNICODE));

            // 接続を切断
            $this->disconnect();

            // 例外を再スロー（カスタム例外でラッピングも可能）
            throw new DatabaseException(
                '学生情報の取得中にデータベースエラーが発生しました: ' . $e->getMessage(),
                $e->getCode(),  //  エラーコード
                ['original_error' => $error_details],  //  context 配列で詳細情報を渡す
                $e->getCode(),  //  SQLSTATEコード
                $e->errorInfo[1] ?? null,  //  ドライバーエラーコード
                $e  // previous exception
            );
        } catch (Exception $e) {
            // その他の例外
            error_log('DBManager Exception: ' . $e->getMessage());
            $this->disconnect();

            // 元の例外を再スロー
            throw $e;
        }
        $this->disconnect();
        return null;
        //  何らかの理由で Exception で
        // とらえられないエラーが起こった場合は null を返す
    }
    //  if_id_exists メソッドは、
    // 指定された ID の学生が
    // 存在するかどうかを確認するメソッドです。
    //  存在する場合は true を、存在しない場合は false を返します。
    public function if_id_exists($id)
    {
        if ($this->get_student($id) !== null) {
            return true; //  学生が存在する場合は true を返す
        }
        return false; //  学生が存在しない場合は false を返す
    }


    //  insert_student メソッドは、
    // 新しい学生情報をデータベースに挿入するメソッドです。
    public function insert_student($id, $name, $grade)
    {

        try {
            //  データベースに接続
            $this->connect();
            $sql = 'INSERT INTO student (id, name, grade) 
                    VALUES (:id, :name, :grade)';
            $stmt = $this->db->prepare($sql);
            //  プレースホルダーに値をバインド
            $stmt->bindValue(':id', $id, PDO::PARAM_INT);
            $stmt->bindValue(':name', $name, PDO::PARAM_STR);
            $stmt->bindValue(':grade', $grade, PDO::PARAM_INT);
            $res = $stmt->execute();
            ///  切断
            $this->disconnect();
            //  execute() の戻り値は、
            //  成功した場合は true、失敗した場合は false です。
            if ($res) {
                return true; //  挿入に成功した場合は true を返す
            }
        } catch (PDOException $e) {
            //  データベースから切断
            $this->disconnect();
            return false; //  挿入に失敗した場合は false を返す
            $error_details = [
                'method' => 'insert_student',
                'id' => $id,
                'name' => $name,
                'grade' => $grade,
                'sqlstate' => $e->getCode(),  // SQLSTATEエラーコードを取得(PDOのとき)
                'driver_code' => $e->errorInfo[1] ?? null,  // ドライバーエラーコードを取得
                'message' => $e->getMessage(),  // エラーメッセージを取得(PDOでは自動的に付与される)
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ];
            error_log('DBManager PDOException: ' . json_encode($error_details, JSON_UNESCAPED_UNICODE));

            // 例外を再スロー（カスタム例外でラッピングも可能）
            throw new DatabaseException(
                '学生情報の挿入中にデータベースエラーが発生しました: ' . $e->getMessage(),
                $e->getCode(),  //  エラーコード
                ['original_error' => $error_details],  //  context 配列で詳細情報を渡す
                $e->getCode(),  //  SQLSTATEコード
                $e->errorInfo[1] ?? null,  //  ドライバーエラーコード
                $e  // previous exception
            );
        }
        //  何らかの理由で Exception でとらえられなかったエラーが起こった場合は
        //  ここで処理します。
        $error_details = [
            'method' => 'insert_student',
            'id' => $id,
            'name' => $name,
            'grade' => $grade,
        ];
        error_log('Unexpected Error: ' . json_encode($error_details, JSON_UNESCAPED_UNICODE));
        // 接続を切断
        $this->disconnect();
        return false; //  挿入に失敗した場合は false を返す
    }

    //  delete_student メソッドは、$idで指定された学生情報を
    //  データベースから削除するメソッドです。
    public function delete_student($id)
    {
        try {
            //  データベースに接続
            $this->connect();
            //  SQL 文を準備
            $sql = 'DELETE FROM student WHERE id = :id';
            $stmt = $this->db->prepare($sql);
            //  プレースホルダーに値をバインド
            $stmt->bindValue(':id', $id, PDO::PARAM_INT);
            //  SQL 文を実行
            $res = $stmt->execute();
            //  execute() の戻り値は、
            //  成功した場合は true、失敗した場合は false です。
            //  $res が true の場合は、削除に成功したことを意味します。
            if ($res) {
                //  データベースから切断
                $this->disconnect();
                return true; //  削除に成功した場合は true を返す
            }
        } catch (PDOException $e) {
            //  データベースから切断
            $this->disconnect();
            return false; //  削除に失敗した場合は false を返す
        }
        $this->disconnect();
        return false; //  削除に失敗した場合は false を返す
        //     **205行目・206行目（`$this->disconnect(); return false;`）
        // は記述しておくほうが安全です**。

        // ### 理由

        // - `setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);` 
        // の指定により、  
        //   通常は`execute()`でエラーが発生した場合は
        // 例外（PDOException）がスローされ、catchブロックで処理されます。
        // - しかし、**何らかの理由で例外が発生しない場合**
        // （たとえば、PDOのバージョンや設定の違い、
        // またはSQL自体は構文的に正しいが影響行が0件など）、
        // catchに入らずにtryブロックの後ろまで進む可能性があります。

        // ### まとめ

        // - **catchで捕まえられなかった異常時や、
        // execute()がfalseを返した場合の保険として、
        // try-catchの外側にも`$this->disconnect(); return false;
        // `を記述しておくのが堅牢な実装です。**
        // - これにより、どんな場合でも確実に接続解除とエラー値の返却が行われます。

        // ---

        // **結論：205行目・206行目は残しておくべきです。**
    }
    //  update_student メソッドは、$old_id で指定された学生情報を
    //  $new_id, $new_name, $new_grade 
    // で指定された新しい情報に更新するメソッドです。
    public function update_student($new_id, $new_name, $new_grade, $old_id)
    {
        try {
            //  データベースに接続
            $this->connect();
            //  SQL 文を準備
            $sql = 'UPDATE student
                    SET 
                        id = :new_id, 
                        name = :new_name,
                        grade = :new_grade
                    WHERE id = :old_id';
            $stmt = $this->db->prepare($sql);
            //  プレースホルダーに値をバインド
            $stmt->bindValue(':new_id', $new_id, PDO::PARAM_INT);
            $stmt->bindValue(':new_name', $new_name, PDO::PARAM_STR);
            $stmt->bindValue(':new_grade', $new_grade, PDO::PARAM_INT);
            $stmt->bindValue(':old_id', $old_id, PDO::PARAM_INT);
            //  SQL 文を実行
            $res = $stmt->execute();
            //  execute() の戻り値は、
            //  成功した場合は true、失敗した場合は false です。
            //  $res が true の場合は、更新に成功したことを意味します。
            if ($res) {
                //  データベースから切断
                $this->disconnect();
                return true; //  更新に成功した場合は true を返す
            }
        } catch (PDOException $e) {
            //  データベースから切断
            $this->disconnect();
            return false; //  更新に失敗した場合は false を返す
        }


        // この部分（try-catchの外側）は、**例外（PDOException）としてcatchできなかった場合**や、  
        // `$stmt->execute()`がfalseを返したけれど例外が発生しなかった場合など、  
        // **catchブロックに入らなかったエラーや失敗時の処理**と考えて問題ありません。

        // ---



        // - try内でSQL実行が失敗しても例外が発生しなかった場合
        // - catchで捕まえられなかったその他の異常時

        // このような場合に、`$this->disconnect(); return false;`が実行されます。  
        // **「catchできなかったエラーや失敗時の保険的な処理」**です。

        $this->disconnect();
        return false; //  更新に失敗した場合は false を返す
    }
}
