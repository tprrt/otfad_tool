## Introduction:

Key scrambler tool uses the scrambling mechanism in OTFAD to scramble the OTFAD
key which is used to encrypt the Image encryption key (IEK). The scrambled OTFAD
key is then used to unwrap the IEK by OTFAD engine.

********************************************************************************
## Description:

Key scrambling is a configurable feature availble in OTFAD engine. The MX7ULP 
chip can be enable this feature in order to use a scrambled OTFAD key instead of
the OTFAD key itself to wrap/unwrap the IEK. This method applies reordering of 
the bits or nibbles within the byte, thus providing extra protection and 
difficulty in capturing the real value of the Key encryption key (OTFAD key).

Key scrambling tool takes in OTFAD key which is to be scrambled using the 
scramble key and alignment data used to reorder the bits. The output is a 
scrambled OTFAD key.

```text
                                      +---------+
+---------+       +-------------+     |         |    +--------------+     +---------+
|  IEK    |------>|   Key Blob  |---->|         |--->|  Key Blob    |---->|  IEK    |
+---------+       +-------------+     |         |    +--------------+     +---------+
    ^ Key Wrap                        |         |         ^  Key Unwrap
    |                                 |    M    |         |
+------------------------+            |    X    |   +-----------------------+
| Key Scrambler - Host   |            |    7    |   | Key Scrambler - OTFAD |
+------------------------+            |    U    |   +-----------------------+
    ^                                 |    L    |         ^
    |                                 |    P    |         |
+-----------------------------+       |         |    +-------------------------+
|      OTFAD Key (KEK)        |------>|         |--->|     OTFAD Key (KEK)     |
+-----------------------------+       |         |    +-------------------------+
                                      +---------+
```

********************************************************************************

### Build:

```make```

### Build with DEBUG enabled:

```make DEBUG=1```

********************************************************************************

## Clean:

```make clean```

********************************************************************************

## Usage:

```text
        ./key_scramble (Sample test values used. Output is stdout.)
        ./key_scramble -i <otfad-key> -k <key-scramble> -a <key-scramble-align> -c <context> -o <output> 
Options:
        -i|--otfad-key  -->  Input OTFAD key (128-bit)
        -k|--key-scramble  -->  Input Scrambled key (32-bit)
        -a|--key-scramble-align  -->  Input Key Align (8-bit)
        -c|--context  -->  Context
        -o|--output  -->  Output File
        -h|--help  -->  This text
```
********************************************************************************
## Examples:
```text
./key_scrambler --otfad-key otfad_key --key-scramble key_scramble --key-scramble-align 0xFF --context 0 --output otfad_scrambled_key
./key_scrambler -i otfad_key -k key_scramble -a 0xFF -c 0 -o otfad_scrambled_key
```
