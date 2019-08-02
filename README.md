## OTFAD in MX7ULP
---
### This package comprises of 3 tools:
1. **Key scrambler tool**          - Scrambles the input OTFAD key
2. **Key wrap tool**               - Wraps the Image Encryption Key (IEK) with
                                     the scrambled OTFAD key
3. **Encrypt Image tool**          - Encrypts the boot image with the IEK

- **build_otfad_enc_image.py**     - Python script to parse YAML configuration
                                     file and generate an encrypted OTFAD image
- **otfag_cfg.yaml**               - Configuration file for OTFAD parameters

### Prerequisites:
---
- xxd
- OpenSSL
- Python
- Pyyaml
  - pip install pyyaml (Python 2)
  - pip3 install pyyaml (Python 3)


### Build steps
---

The Key scrambler, Key wrap and Encrypt Image tools can be build, with or
without DEBUG enabled, individually or all tools can be build using make
command.

- DEBUG not enabled
  - ```make```

- DEBUG enabled
  - ```make DEBUG=1```

### Step by Step process:
---
1. ***Create OTFAD key:***

- Using OpenSSL
  - ```openssl rand -hex 16 | xxd -r -p > otfad_key```

2. ***Create Image encryption key, Counter, Key Scramble:***

- Using OpenSSL
  - ```openssl rand -hex 16 | xxd -r -p > enc_key```
  - ```openssl rand -hex 8 | xxd -r -p > ctr```
  - ```openssl rand -hex 4 | xxd -r -p > key_scramble```

3. ***Fill the otfad_cfg.yaml file with proper infomation:***

#### Sample configuration file:
```text
# Global I/O
otfad_key: "otfad_key"
key_scramble: "key_scramble"
key_scramble_align: 0x11
input_image: "ulp_m4.bin"
output_file: "otfad.bin"

# Boot image partitions I/O
boot_image_part1:
  image_offset: 0x1000
  size: 0x2000
  image_enc_key: "enc_key1"
  counter: "ctr1"

boot_image_part2:
  image_offset: 0x3000
  size: 0x2000
  image_enc_key: "enc_key2"
  counter: "ctr2"

boot_image_part3:
  image_offset: 0x5000
  size: 0x2000
  image_enc_key: "enc_key3"
  counter: "ctr3"

boot_image_part4:
  image_offset: 0x7000
  size: 0x2000
  image_enc_key: "enc_key4"
  counter: "ctr4"
```

4. ***Prepare the final OTFAD encrypted image***

The final OTFAD encrypted image can be build by using the Python script
along with the configuration file as follows:
- ```python build_otfad_enc_image.py otfad_cfg.yaml```

The python script also prints the fuses to burn as follows:

```text
Printing OTFAD key...
Burn OTFAD key as follows:
OTFAD KEY[0]: 0xFFEEDDCC
OTFAD KEY[1]: 0xBBAA9988
OTFAD KEY[2]: 0x77665544
OTFAD KEY[3]: 0x33221100

Printing Key Scramble and Key Scramble Align...
Burn Key Scramble as follows:
KEY SCRAMBLE[0]: 0x12345678
Burn Key Scramble Align as follows:
KEY SCRAMBLE ALIGN[0]: 0x00001200
```

#### Input image:

```text
+------------------------------+   <-- 0x0
|                              |
|         --Padding--          |
|                              |
|------------------------------|   <-- 0x400
|       QSPI Configuration     |
|------------------------------|   <-- 0x600
|         --Padding--          |
|------------------------------|   <-- 0x1000
|      Plaintext Boot Image    |
+------------------------------+
```

#### Final output image:

```text
+------------------------------+   <-- 0x0
|          KeyBlob 0           |
|------------------------------|   <-- 0x40
|          KeyBlob 1           |
|------------------------------|   <-- 0x80
|          KeyBlob 2           |
|------------------------------|   <-- 0xC0
|          KeyBlob 3           |
|------------------------------|   <-- 0x100
|         --Padding--          |
|------------------------------|   <-- 0x400
|       QSPI Configuration     |
|------------------------------|   <-- 0x600
|         --Padding--          |
|------------------------------|   <-- 0x1000
|      Encrypted Boot Image    |
+------------------------------+
```

- Resultant encrypted boot image will be present in result folder.

5. ***Program and burn the fuses on the MX7ULP***

Using u-boot fuse utility, fuses can be burned as follows:

***NOTE: Certain Fuses in MX7ULP are in ECC mode, thus a fuse word can be programmed only once.***

- Burn the OTFAD key eFuse
  - ```fuse prog 29 0 0xXXXXXXXX 0xXXXXXXXX 0xXXXXXXXX 0xXXXXXXXX```

- Program Scrambling key
  - ```fuse prog 29 7 0xXXXXXXXX```

- Program Key scramble align
  - ```fuse prog 29 4 0x0000XX00```

- Enable Key Scramble
  - ```fuse prog 29 4 0x00000080```

- Enable OTFAD
  - ```fuse prog 29 4 0x00000020```

6. ***Program QSPI image***

QSPI image can be programmed in different ways. Here is an example using u-boot cli.

- Download Encrypted M4 boot image from SD card
  - ```fatload mmc 0:1 0x67900000 otfad.bin```

- Program QSPI using u-boot cli

***NOTE: After enabling OTFAD, if you are unable to probe QSPI, then disable OTFAD via software
using ```mw 0x410A5C00 0xc0000068``` command and re-try.***

  - ```sf probe```
  - ```sf erase 0 0x10000```
  - ```sf write 0x67900000 0 0x10000```

7. ***Reboot***
