# Encrypt Image tool
---
## Introduction:
---
The Encrypt Image tool uses AES-128-CTR encryption algorithm to encrypt the boot
image based on the input parameters provided. As OTFAD supports 4 contexts, the
input image can be divided upto 4 different images which can be encrypted using
their own image encryption key (IEK) and counter values.

## Description:
---
The boot image encryption is an AES-128-CTR operation. It uses an IEK and 
counter, as used in the key wrapping tool, to encrypt an input boot image. The 
boot image for MX7ULP M4 starts at an offset 0x1000, thus the boot image can 
only be encrypted from 0x1000 offset.

A typical input image looks like below (with offsets):

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

The output looks like below (with offsets) when complete image is encrypted with
one IEK:

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
|      Encrypted Boot Image    |
+------------------------------+
```

## Build:
---
```make```


## Build with DEBUG enabled:
---
```make DEBUG=1```


## Clean:
---
```make clean```

## Usage:
---
```text
        ./encrypt_image -i <input-image> -k <enc-key> -c <counter> -s <start-address> -e <end-address> -o <output> 
Options:
        -i|--input-image  -->  Input image to be decrypted
        -k|--enc-key  -->  Input image encryption key (128-bit)
        -c|--counter  -->  Input counter (64 bit)
        -s|--start-address  -->  Start Address of encryption in File (32-bit)
        -e|--end-address  -->  End Address of encryption in File (32-bit)
        -o|--output  -->  Output File
        -h|--help  -->  This text
```

## Examples:
---
```text
./encrypt_image --input-image ulp-m4_signed.bin --enc-key key --counter ctr --start-address 0xC0001000 --end-address 0xC0008000 --output ulp-m4_signed.bin_no_header
./encrypt_image -i ulp-m4_signed.bin -k key -c ctr -s 0xC0001000 -e 0xC0008000 -o ulp-m4_signed.bin_no_header

```
