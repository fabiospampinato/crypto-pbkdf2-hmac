
/* IMPORT */

import benchmark from 'benchloop';
import pbkdf2 from '../dist/index.js';

/* HELPERS */

const INPUT_SECRET = 'P@ssword!';
const INPUT_SALT = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';

/* MAIN */

benchmark.config ({
  iterations: 100
});

for ( const format of ['buffer', 'uint8', 'hex'] ) {

  benchmark.group ( format, () => {

    benchmark ({
      name: 'SHA-1',
      fn: async () => {
        await pbkdf2.sha1[format]( INPUT_SECRET, INPUT_SALT, 1000, 20 );
      }
    });

    benchmark ({
      name: 'SHA-256',
      fn: async () => {
        await pbkdf2.sha256[format]( INPUT_SECRET, INPUT_SALT, 1000, 32 );
      }
    });

    benchmark ({
      name: 'SHA-384',
      fn: async () => {
        await pbkdf2.sha384[format]( INPUT_SECRET, INPUT_SALT, 1000, 48 );
      }
    });

    benchmark ({
      name: 'SHA-512',
      fn: async () => {
        await pbkdf2.sha512[format]( INPUT_SECRET, INPUT_SALT, 1000, 64 );
      }
    });

  });

}

benchmark.summary ();
