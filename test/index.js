
/* IMPORT */

import {describe} from 'fava';
import pbkdf2 from '../dist/index.js';

/* MAIN */

describe ( 'Crypto PBKDF2', it => {

  it ( 'supports sha1', async t => {

    const tests = [
      [
        'P@ssword!',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        1000,
        20,
        'a580873960d83dc5b1b6606c3ddf289dcb049b61'
      ],
      [
        'P@ssword1',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        1000,
        20,
        '50aaa6d722b3d0f919e69e30d30461762473a99c'
      ],
      [
        'P@ssword!',
        '0a39a3ee5e6b4b0d3255bfef95601890afd80709',
        1000,
        20,
        '40d2d6a1ec93dc708628cc807af4ed0d8097284e'
      ],
      [
        'P@ssword!',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        10000,
        20,
        'cf301c658a16c484685f5fb1f825f49d2647477e'
      ],
      [
        'P@ssword!',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        1000,
        10,
        'a580873960d83dc5b1b6'
      ],
      [
        '\u0041\u006d\u00e9\u006c\u0069\u0065',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        1000,
        20,
        '975bf63040485d70fa7090a7c56e8e74b2988fec'
      ],
      [
        '\u0041\u006d\u0065\u0301\u006c\u0069\u0065',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        1000,
        20,
        '975bf63040485d70fa7090a7c56e8e74b2988fec'
      ]
    ];

    for ( const [input, salt, iterations, bytesLength, output] of tests ) {

      t.is ( await pbkdf2.sha1 ( input, salt, iterations, bytesLength ), output );
      t.is ( await pbkdf2.sha1 ( Buffer.from ( input.normalize () ), Buffer.from ( salt ), iterations, bytesLength ), output );
      t.is ( ( await pbkdf2.sha1 ( input, salt, iterations, bytesLength ) ).length, bytesLength * 2 );

    }

  });

  it ( 'supports sha256', async t => {

    const tests = [
      [
        'P@ssword!',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        1000,
        32,
        '92cd21bbad02134ce5bb3ef571619ec6a55ba1d9471f571f80c7a009a36b0662'
      ],
      [
        'P@ssword1',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        1000,
        32,
        '7b0a593ffa563c219757c0ca2d1b45d271550ab00789a0b34eec5bfa44610c42'
      ],
      [
        'P@ssword!',
        '03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        1000,
        32,
        'e374f416dbd7f799d714697e51b5c6aac4aa1943569c05382f8a2af86b78dbc9'
      ],
      [
        'P@ssword!',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        10000,
        32,
        'f72ffbad478bba0443ecd6f107666f61ba89be2a71d15f6a440bbb0b914cddc6'
      ],
      [
        'P@ssword!',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        1000,
        16,
        '92cd21bbad02134ce5bb3ef571619ec6'
      ],
      [
        '\u0041\u006d\u00e9\u006c\u0069\u0065',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        1000,
        32,
        'f957b8912d241f504a7d415f66f0c405d611039644f13e045d15934772ee2fbc'
      ],
      [
        '\u0041\u006d\u0065\u0301\u006c\u0069\u0065',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        1000,
        32,
        'f957b8912d241f504a7d415f66f0c405d611039644f13e045d15934772ee2fbc'
      ]
    ];

    for ( const [input, salt, iterations, bytesLength, output] of tests ) {

      t.is ( await pbkdf2.sha256 ( input, salt, iterations, bytesLength ), output );
      t.is ( await pbkdf2.sha256 ( Buffer.from ( input.normalize () ), Buffer.from ( salt ), iterations, bytesLength ), output );
      t.is ( ( await pbkdf2.sha256 ( input, salt, iterations, bytesLength ) ).length, bytesLength * 2 );

    }

  });

  it ( 'supports sha384', async t => {

    const tests = [
      [
        'P@ssword!',
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        1000,
        48,
        'bd80cdf1c55fedfbb4f5692c9d41a63f5606d335d0d6f7a04031ac34a55e78eadfcf2dc6d64e3522fe08c2720a1007f8'
      ],
      [
        'P@ssword1',
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        1000,
        48,
        '5d6bdc2962d5bf8b5402ace5af9875582393bdb30f11203c139342d4c20c994ac3753ef061aced90ca7fd0bf40e179a2'
      ],
      [
        'P@ssword!',
        '08b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        1000,
        48,
        'f223610a0ee17ff22fb15d523acfc82c6098781ab6b39c0dbec1e47498d33b6e904d403142d8d0aaae05a67b6d29825b'
      ],
      [
        'P@ssword!',
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        10000,
        48,
        'b7af1211dd38332cb9dafb17d03a2a7fe0694be712ab15fdfdadd847214bddb2ebf435656f60d8b4c84a5bd8c5f09292'
      ],
      [
        'P@ssword!',
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        1000,
        24,
        'bd80cdf1c55fedfbb4f5692c9d41a63f5606d335d0d6f7a0'
      ],
      [
        '\u0041\u006d\u00e9\u006c\u0069\u0065',
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        1000,
        48,
        '23f1b32dd9622558ac34ae1b0878785d82f4f02547321118f1d9ed7be032c73b5fd580536ec26ec18c92bed9933359ad'
      ],
      [
        '\u0041\u006d\u0065\u0301\u006c\u0069\u0065',
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        1000,
        48,
        '23f1b32dd9622558ac34ae1b0878785d82f4f02547321118f1d9ed7be032c73b5fd580536ec26ec18c92bed9933359ad'
      ]
    ];

    for ( const [input, salt, iterations, bytesLength, output] of tests ) {

      t.is ( await pbkdf2.sha384 ( input, salt, iterations, bytesLength ), output );
      t.is ( await pbkdf2.sha384 ( Buffer.from ( input.normalize () ), Buffer.from ( salt ), iterations, bytesLength ), output );
      t.is ( ( await pbkdf2.sha384 ( input, salt, iterations, bytesLength ) ).length, bytesLength * 2 );

    }

  });

  it ( 'supports sha512', async t => {

    const tests = [
      [
        'P@ssword!',
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        1000,
        64,
        '08da1ff855ae75740d1480414f9f08dc217061591c41eb71224aa8be7b36c78b98d4b141e8cfd11e54f9477b4017c52b24d8bae8eba21424f1504858d03780fd'
      ],
      [
        'P@ssword1',
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        1000,
        64,
        '009405588db061594d67010e9cb586c9e95c989374504a8c8b2800e079e76a75e06c0c2ad8c35f71cc91de19b99131abba49cba7c245cf92629a466b8cf43c8f'
      ],
      [
        'P@ssword!',
        '0f83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        1000,
        64,
        '2ee4ee87f2612864e2d0b83d05692e0dcca1683c39c4b2c213132cb5160f9795eb36f11458447989872df67a8297cfdb2d8eae2af528e3d11c0d1504c18149c7'
      ],
      [
        'P@ssword!',
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        10000,
        64,
        '3b0d3aca2968ddc8d077162b648586136be763ea7f2f71e09673c67c094d28fc12d7ba1a03939a76bdcb74f681542b6ce99feeaa240c911974cf1c6610dc01d0'
      ],
      [
        'P@ssword!',
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        1000,
        32,
        '08da1ff855ae75740d1480414f9f08dc217061591c41eb71224aa8be7b36c78b'
      ],
      [
        '\u0041\u006d\u00e9\u006c\u0069\u0065',
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        1000,
        64,
        '0e1b0d8056784e3524391d03870bede318ef864b76d38e9365dad5a20a39226b69b7a428da265f4d0e70007352eae24fe37d66e057078e0ad7080831f93c785e'
      ],
      [
        '\u0041\u006d\u0065\u0301\u006c\u0069\u0065',
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        1000,
        64,
        '0e1b0d8056784e3524391d03870bede318ef864b76d38e9365dad5a20a39226b69b7a428da265f4d0e70007352eae24fe37d66e057078e0ad7080831f93c785e'
      ]
    ];

    for ( const [input, salt, iterations, bytesLength, output] of tests ) {

      t.is ( await pbkdf2.sha512 ( input, salt, iterations, bytesLength ), output );
      t.is ( await pbkdf2.sha512 ( Buffer.from ( input.normalize () ), Buffer.from ( salt ), iterations, bytesLength ), output );
      t.is ( ( await pbkdf2.sha512 ( input, salt, iterations, bytesLength ) ).length, bytesLength * 2 );

    }

  });

});
