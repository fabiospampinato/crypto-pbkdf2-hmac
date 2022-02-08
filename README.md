# Crypto PBKDF2-HMAC

Isomorphic wrapper for the PBKDF2-HMAC key derivation function.

## Install

```sh
npm install --save crypto-pbkdf2-hmac
```

## Usage

```ts
import pbkdf2 from 'crypto-pbkdf2-hmac';

await pbkdf2.sha1 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 20 ); // => 'a580873960d83dc5b1b6606c3ddf289dcb049b61'
await pbkdf2.sha256 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 32 ); // => 'ca768ef0b0eedfafe1cf4961b72dc523d66ff4730ecab9320e3d1ab3eecb5fa0'
await pbkdf2.sha384 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 48 ); // => '52ec30653d24d8b4bf3b1b8d6f20a6778115be23e66b93cbdedf523c82109b1a2a521c7219eae544c8de1c625291540a'
await pbkdf2.sha512 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 64 ); // => 'e6f8a7b90d9d5aa236d24d307c9bda5054eea2926b35c88ef9fc12c7b26532943f3dbf57d44e9d3c1804e393d4e693e86601a39c9e5e77200c97e23e0abc67a8'
```

## License

MIT © Fabio Spampinato
