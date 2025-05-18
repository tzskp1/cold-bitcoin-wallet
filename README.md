
設計方針
- 機能を絞ることでattack surfaceを最小化する
- cryptographic primitivesやデファクトスタンダードライブラリをのぞき自前の実装をつかうことでサプライチェーン攻撃のリスクをさげる
  - bitcoinに対する理解を深める意味もある
- できるかぎりのバリデーションを行う
- 最低限の互換性のサポート
- 抽象化よりもコードベースを小さく保つことを優先する

## TODO
- hd wallet
- taproot
- make transaction
- validate witver & length

- fix to_5bits
