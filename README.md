# Java SDK for The Open Network (TON)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Based on TON][ton-svg]][ton]
![GitHub last commit](https://img.shields.io/github/last-commit/neodiX42/ton4j)

Java libraries for interacting with TON blockchain. 

## Maven [![Maven Central][maven-central-svg]][maven-central]

```xml
<dependency>
    <groupId>io.github.neodix42</groupId>
    <artifactId>smartcontract</artifactId>
    <version>0.0.2</version>
</dependency>
```

## Jitpack [![JitPack][jitpack-svg]][jitpack]

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

```xml
<dependency>
    <groupId>io.github.neodix42</groupId>
    <artifactId>ton4j</artifactId>
    <version>0.0.2</version>
</dependency>
```

You can use each sub-module individualy. Click the module below to get more details.

* [Tonlib](tonlib/README.md) - use external Tonlib shared library to communicate with TON blockchain.
* [SmartContract](smartcontract/README.md) - create and deploy custom and predefined smart-contracts.
* [Cell](cell/README.md) - create, read and manipulate Bag of Cells.
* [BitString](bitstring/README.md) - construct bitstrings. All data in Cells stored in bitstrings.
* [Address](address/README.md) - create and parse TON wallet addresses.
* [Mnemonic](mnemonic/README.md) - helpful methods for generating deterministic keys for TON blockchain.
* [Utils](utils/README.md) - create private and public keys, convert data.

### Features

* ✅ Cells serialization / deserialization
* ✅ Support num, cell and slice as arguments for runMethod
* ✅ Render List, Tuple, Slice, Cell and Number results from runMethod
* ✅ Generate or import private key, sign, encrypt and decrypt using Tonlib
* ✅ Encrypt/decrypt with mnemonic
* ✅ Get account state method
* ✅ Send external message
* ✅ Get block transactions
* ✅ Get account transactions
* ✅ Deploy contracts and send external messages using Tonlib
* ✅ Wallet operations (Simple, V2, V3, V4, Lockup)
* ✅ Cell hashmap serialization / deserialization

### Todo

* Support tuple and list as arguments for runMethod
* Add TON DNS support
* Add TON Payment channel support
* Add FT (Jetton) and NFT tokens support
* Fix dictionary de/serialization with one entry
* Improve test coverage and add more integration tests

<!-- Badges -->

[maven-central-svg]: https://img.shields.io/maven-central/v/io.github.neodix42/smartcontract

[maven-central]: https://mvnrepository.com/artifact/io.github.neodix42/smartcontract

[jitpack-svg]: https://jitpack.io/v/neodiX42/ton4j.svg

[jitpack]: https://jitpack.io/#neodiX42/ton4j

[ton-svg]: https://img.shields.io/badge/Based%20on-TON-blue

[ton]: https://ton.org