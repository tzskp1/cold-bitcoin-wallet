## このソフトウェアについて
オフラインで動作する最低限な機能をそなえたbitcoinのコールドウォレット実装です

## 設計方針
- 機能を絞ることでattack surfaceを最小化する
- cryptographic primitivesやデファクトスタンダードライブラリを除き自前の実装をつかうことでサプライチェーン攻撃のリスクをさげる
  - bitcoinに対する理解を深める意味もある
- できるかぎりのバリデーションを行う
- 最低限の互換性のサポート
- 抽象化よりもコードベースを小さく保つことを優先する

## 使い方

### Step1: ビルド
まずrustがインストールされた環境でビルドします

```bash
$ cargo build --release
```

できあがったバイナリをオフライン環境に持っていきます

### Step2: HD Walletのシード値を生成

以下のようにコマンドを入力するとプロンプトが出力され パスフレーズを待ち受けます

```bash
$ /path/to/cold-bitcoin-wallet generate seed
Enter Passphrase:
```

ここで入力したパスフレーズを用いて ランダムに生成されたシード値を暗号化します

### Step3: アドレスを生成

以下のようにしてStep2で生成したシードに対応するbitcoinアドレスを生成します

```
$ /path/to/cold-bitcoin-wallet generate address --wallet-path "m/0'/1" --network testnet
Enter Passphrase: ******
Address: tb1pqqj0xeagwy5fdcwg45tfamfx9nrcaz2d8h33qp03nksrudzrqm6syq3vzj
```

ここで入力するパスフレーズはStep2で入力したものと同一である必要があります

### Step4: 送金する

Step3で生成したアドレスになんらかの手段で送金します
([Faucet](https://mempool.space/testnet4/faucet)を使い動作確認しています)
得られた `txid`, `vout`, `金額` を控えておきます

### Step5: トランザクション生成

以下のようなJSONを作成します

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

ここで `inputs` に記入するのは先程控えたパラメータです(`amount` の単位は `satoshi` です)
複数の入力を持つことができますが `private_key_paths` と `inputs` はそれぞれ対応している必要があります
`outputs` については送りたい相手のアドレスと金額(`satoshi`)を記入します
ここでは上のようなJSONを `params.json` とします

このとき以下のようにするとトランザクションが生成されます

```
$ /path/to/cold-bitcoin-wallet sign -p /path/to/params.json
Enter Passphrase: ******
Transaction: 02000000000101d9dbeef7b4cd765ef1f927976745673e9164bd902a287c008ec0e87a06ab59850100000000ffffffff02c409000000000000225120a3359af0b524641a3eefdd89e388dc8f535298a700cb8d8c40b2c845c9b379a8d0070000000000002251200024f367a8712896e1c8ad169eed262cc78e894d3de31005f19da03e344306f50140b75e82d7305c1f868354ac3eedfb9ae94e74b1d707a7442c6405849bcfda50a463b2b9b963199c4c8a7ddbf0742b7f1e04cdb4174301dae1ecf3569061a0cfaa00000000
```

### Step6: ブロードキャスト

`bitcoind` などを用いてStep5の結果をブロードキャストします
