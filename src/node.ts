
/* IMPORT */

import crypto from 'crypto';

/* HELPERS */

const encoder = new TextEncoder ();

const makePbkdf2 = ( algorithm: 'sha1' | 'sha256' | 'sha384' | 'sha512' ) => {

  return ( password: Uint8Array | string, salt: Uint8Array | string, iterations: number, bytesLength: number ): Promise<string> => {

    password = ( typeof password === 'string' ) ? encoder.encode ( password.normalize () ) : password;
    salt = ( typeof salt === 'string' ) ? encoder.encode ( salt ) : salt;

    return new Promise ( ( resolve, reject ) => {

      crypto.pbkdf2 ( password, salt, iterations, bytesLength, algorithm, ( err, key ) => {

        if ( err ) return reject ( err );

        const hex = key.toString ( 'hex' );

        return resolve ( hex );

      });

    });

  };

};

/* MAIN */

const pbkdf2 = {
  sha1: makePbkdf2 ( 'sha1' ),
  sha256: makePbkdf2 ( 'sha256' ),
  sha384: makePbkdf2 ( 'sha384' ),
  sha512: makePbkdf2 ( 'sha512' )
};

/* EXPORT */

export default pbkdf2;
