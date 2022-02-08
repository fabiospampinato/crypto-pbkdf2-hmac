
/* IMPORT */

import toHex from 'uint8-to-hex';

/* HELPERS */

const encoder = new TextEncoder ();

const makePbkdf2 = ( algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512' ) => {

  return async ( password: Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<string> => {

    password = ( typeof password === 'string' ) ? encoder.encode ( password.normalize () ) : password;
    salt = ( typeof salt === 'string' ) ? encoder.encode ( salt ) : salt;

    const key = await crypto.subtle.importKey ( 'raw', password, { name: 'PBKDF2' }, false, ['deriveBits'] );
    const bits = await crypto.subtle.deriveBits ( { name: 'PBKDF2', salt, iterations, hash: { name: algorithm } }, key, bytesLength * 8 );
    const hex = toHex ( new Uint8Array ( bits ) );

    return hex;

  };

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
