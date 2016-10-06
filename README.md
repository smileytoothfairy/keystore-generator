PKCS#12 Keystores Generator Utility
===================================

This project implements a command-line tool for generating [PKCS#12](https://en.wikipedia.org/wiki/PKCS_12)
keystores which can be used with various [X.509](https://en.wikipedia.org/wiki/X.509) tools.

This tool uses [Bouncy Castle](https://www.bouncycastle.org/java.html) crypto library.

Usage
-----

Build distribution:

    mvn clean package -Dmaven.test.skip=true

Generate a keystore using [default config file](https://github.com/akashche/keystore-generator/blob/master/src/main/files/config.json):

    java -jar ./target/keystoregen-1.0-SNAPSHOT-dist/keystoregen.jar -c ./src/main/files/config.json -o keystore.p12

List keystore contents:

    keytool -list -keystore keystore.p12 -storetype pkcs12 -storepass passphrase

License information
-------------------

This project is released under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Changelog
---------

**2016-10-07**

 * initial public version