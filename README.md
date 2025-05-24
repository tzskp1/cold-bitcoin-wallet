## このソフトウェアについて

オフラインで動作する、必要最小限の機能を備えた Bitcoin コールドウォレットの実装です。

## 設計方針

* 機能を最小限に絞り、attack surface を最小化する。
* cryptographic primitives やデファクトスタンダードなライブラリ以外は自前で実装し、サプライチェーン攻撃のリスクを低減する。
  * Bitcoinへの理解を深めることも目的の一つである。
* 可能な限りのバリデーションを実施する。
* 必要最低限の互換性のみサポートする。
* 抽象化よりもコードベースを小さく保つことを優先する。

## 使い方

### Step1: ビルド

まず、Rustがインストールされた環境でビルドします。

```bash
$ cargo build --release
```

生成されたバイナリをオフライン環境に移動させます。

### Step2: HD Walletのシード値を生成

以下のコマンドを入力するとプロンプトが表示され、パスフレーズを要求されます。

```bash
$ /path/to/cold-bitcoin-wallet generate seed
Enter Passphrase:
```

ここで入力したパスフレーズは、生成されたシード値を暗号化するために使われます。

### Step3: アドレスを生成

以下のコマンドで、Step2で生成したシードからBitcoinアドレスを生成します。

```bash
$ /path/to/cold-bitcoin-wallet generate address --wallet-path "m/0'/1" --network testnet
Enter Passphrase: ******
Address: tb1pqqj0xeagwy5fdcwg45tfamfx9nrcaz2d8h33qp03nksrudzrqm6syq3vzj
```

ここで入力するパスフレーズは、Step2で入力したものと同一である必要があります。

### Step4: 送金

Step3で生成したアドレスへ何らかの方法で送金します。

[Faucet](https://mempool.space/testnet4/faucet)を使い動作確認しています。

送金後、`txid`・`vout`・`金額(satoshi)`を記録しておいてください。

### Step5: トランザクションの生成

以下のようなJSONファイルを作成します（ここでは`params.json`とします）。

```json
{
  "inputs": [
    {
      "txid": "8559ab067ae8c08e007c282a90bd64913e6745679727f9f15e76cdb4f7eedbd9",
      "vout": 1,
      "address": "tb1pqqj0xeagwy5fdcwg45tfamfx9nrcaz2d8h33qp03nksrudzrqm6syq3vzj",
      "amount": 5000
    }
  ],
  "outputs": [
    {
      "address": "tb1p5v6e4u94y3jp50h0mky78zxu3af49x98qr9cmrzqktyytjdn0x5qhw96f9",
      "amount": 2500
    },
    {
      "address": "tb1pqqj0xeagwy5fdcwg45tfamfx9nrcaz2d8h33qp03nksrudzrqm6syq3vzj",
      "amount": 2000
    }
  ],
  "private_key_paths": ["m/0'/1"]
}
```

* `inputs` には、Step4で控えた送金元の情報（`txid`、`vout`、`amount`）を入力します。
* 入力が複数ある場合、`private_key_paths` と `inputs` はそれぞれ順序を一致させる必要があります。
* `outputs` には、送金先のアドレスと金額（単位は`satoshi`）を指定します。

以下のコマンドでトランザクションを生成します。

```bash
$ /path/to/cold-bitcoin-wallet sign -p /path/to/params.json
Enter Passphrase: ******
Transaction: 02000000000101d9dbeef7b4cd765ef1f927976745673e9164bd902a287c008ec0e87a06ab59850100000000ffffffff02c409000000000000225120a3359af0b524641a3eefdd89e388dc8f535298a700cb8d8c40b2c845c9b379a8d0070000000000002251200024f367a8712896e1c8ad169eed262cc78e894d3de31005f19da03e344306f50140b75e82d7305c1f868354ac3eedfb9ae94e74b1d707a7442c6405849bcfda50a463b2b9b963199c4c8a7ddbf0742b7f1e04cdb4174301dae1ecf3569061a0cfaa00000000
```

### Step6: ブロードキャスト

生成したトランザクションを、オンライン環境の `bitcoind` やウォレットサービスを用いてブロードキャストします。
