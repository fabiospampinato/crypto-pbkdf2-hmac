
/* IMPORT */

import toHex from 'uint8-to-hex';
import webcrypto from 'tiny-webcrypto';

/* HELPERS */

const encoder = new TextEncoder ();

const makePbkdf2 = ( algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512' ) => {

  const buffer = async ( password: Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<ArrayBuffer> => {

    password = ( typeof password === 'string' ) ? encoder.encode ( password.normalize () ) : password;
    salt = ( typeof salt === 'string' ) ? encoder.encode ( salt ) : salt;

    const key = await webcrypto.subtle.importKey ( 'raw', password, { name: 'PBKDF2' }, false, ['deriveBits'] );
    const buffer = await webcrypto.subtle.deriveBits ( { name: 'PBKDF2', salt, iterations, hash: { name: algorithm } }, key, bytesLength * 8 );

    return buffer;

  };

  const uint8 = async ( password: Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<Uint8Array> => {

    return new Uint8Array ( await buffer ( password, salt, iterations, bytesLength ) );

  };

  const hex = async ( password: Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<string> => {

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
