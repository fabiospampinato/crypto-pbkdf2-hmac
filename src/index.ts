
/* IMPORT */

import toHex from 'uint8-to-hex';
import webcrypto from 'tiny-webcrypto';

/* HELPERS */

const encoder = new TextEncoder ();

const makePbkdf2 = ( algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512' ) => {

  const bufferKey = async ( password: CryptoKey | Uint8Array | string ): Promise<CryptoKey> => {

    if ( password instanceof Uint8Array ) {

      return webcrypto.subtle.importKey ( 'raw', password, { name: 'PBKDF2' }, false, ['deriveBits'] );

    } else if ( typeof password === 'string' ) {

      return bufferKey ( encoder.encode ( password.normalize () ) );

    } else {

      return password;

    }

  };

  const bufferBits = ( password: CryptoKey, salt: Uint8Array | string, iterations: number, bitsLength: number ): Promise<ArrayBuffer> => {

    salt = ( typeof salt === 'string' ) ? encoder.encode ( salt ) : salt;

    return webcrypto.subtle.deriveBits ( { name: 'PBKDF2', salt, iterations, hash: { name: algorithm } }, password, bitsLength );

  };

  const buffer = async ( password: CryptoKey | Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<ArrayBuffer> => {

    const key = await bufferKey ( password );
    const bits = await bufferBits ( key, salt, iterations, bytesLength * 8 );

    return bits;

  };

  const uint8 = async ( password: CryptoKey | Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<Uint8Array> => {

    return new Uint8Array ( await buffer ( password, salt, iterations, bytesLength ) );

  };

  const hex = async ( password: CryptoKey | Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<string> => {

    return toHex ( await uint8 ( password, salt, iterations, bytesLength ) );

  };

  hex.buffer = buffer;
  hex.hex = hex;
  hex.uint8 = uint8;

  return hex;

};

/* MAIN */

const pbkdf2 = {
  sha1: makePbkdf2 ( 'SHA-1' ),
  sha256: makePbkdf2 ( 'SHA-256' ),
  sha384: makePbkdf2 ( 'SHA-384' ),
  sha512: makePbkdf2 ( 'SHA-512' )
};

/* EXPORT */

export default pbkdf2;
