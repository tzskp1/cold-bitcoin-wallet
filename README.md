## 設計方針
- 機能を絞ることでattack surfaceを最小化する
- cryptographic primitivesやデファクトスタンダードライブラリを除き自前の実装をつかうことでサプライチェーン攻撃のリスクをさげる
  - bitcoinに対する理解を深める意味もある
- できるかぎりのバリデーションを行う
- 最低限の互換性のサポート
- 抽象化よりもコードベースを小さく保つことを優先する

## TODO
- taproot
- make transaction
- validate witver & length

## MEMO
- cargo run -- generate address --wallet_path "m/0'/1" --network testnet
- https://coinfaucet.eu/en/btc-testnet/
- tx: 69e071c605f147f3a5c97c1474c16e0f0527823633aee2a645a74693ac8ed1db
- https://mempool.space/testnet/tx/69e071c605f147f3a5c97c1474c16e0f0527823633aee2a645a74693ac8ed1db
