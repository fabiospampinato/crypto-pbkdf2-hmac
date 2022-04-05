
/* IMPORT */

import pbkdf2 from '../dist/index.js';

/* MAIN */

const benchmark = async () => {

  console.time ( 'benchmark' );

  console.time ( 'benchmark.sha1' );
  for ( let i = 0, l = 100; i < l; i++ ) {
    await pbkdf2.sha1 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 20 );
  }
  console.timeEnd ( 'benchmark.sha1' );

  console.time ( 'benchmark.sha256' );
  for ( let i = 0, l = 100; i < l; i++ ) {
    await pbkdf2.sha256 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 32 );
  }
  console.timeEnd ( 'benchmark.sha256' );

  console.time ( 'benchmark.sha384' );
  for ( let i = 0, l = 100; i < l; i++ ) {
    await pbkdf2.sha384 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 48 );
  }
  console.timeEnd ( 'benchmark.sha384' );

  console.time ( 'benchmark.sha512' );
  for ( let i = 0, l = 100; i < l; i++ ) {
    await pbkdf2.sha512 ( 'P@ssword!', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 1000, 64 );
  }
  console.timeEnd ( 'benchmark.sha512' );

  console.timeEnd ( 'benchmark' );

};

benchmark ();
