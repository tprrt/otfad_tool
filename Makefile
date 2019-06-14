# Makefile to build the tools

KEY_SCRAMBLER_DIR:= key_scrambler
KEY_WRAP_DIR := key_wrap
ENCRYPT_IMAGE_DIR := encrypt_image

ifeq ($(DEBUG), 1)
OPT := DEBUG=1
endif

all:
		@$(MAKE) -sC $(KEY_SCRAMBLER_DIR) $(OPT)
		@$(MAKE) -sC $(KEY_WRAP_DIR) $(OPT)
		@$(MAKE) -sC $(ENCRYPT_IMAGE_DIR) $(OPT)

clean:
		@$(MAKE) -sC $(KEY_SCRAMBLER_DIR) clean
		@$(MAKE) -sC $(KEY_WRAP_DIR) clean
		@$(MAKE) -sC $(ENCRYPT_IMAGE_DIR) clean
		@$(RM) -rf result

