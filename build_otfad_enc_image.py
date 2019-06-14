#! /usr/bin/env python

import os
import shutil
import sys
import yaml
import subprocess
import binascii

#
# Initialize boot image partitions parameters
#
class boot_image_part():
	''' Initialize boot image partitions parameters '''
	def __init__(self, img_offset, size, image_enc_key, counter, is_enabled, part_num):
		self.en = is_enabled
		self.num = part_num
		self.offset = img_offset
		self.size = size
		self.enc_key = image_enc_key
		self.ctr = counter
		self.srt_addr = MX7ULP_QSPI_BASE_ADDR + img_offset
		self.end_addr = self.srt_addr + size
		self.end_addr_kb = self.srt_addr + size
		self.keyblob = res_path + "keyblob" + str(part_num)
		self.enc_image = res_path + "enc_image" + str(part_num)
		self.scrambled_kek = res_path + "otfad_scrambled_key" + str(part_num)

#
# Prints Key Scramble, to be burned in the chip, on the screen
#
def print_key_scramble(key_scramble):
	'''
	Prints Key Scramble, to be burned in the chip, on the screen
	'''
	# Print Key Scramble in little-endian format as per OTFAD for burning the Fuse
	print ("Burn Key Scramble as follows:")

	key_scramble_data = []
	with open(key_scramble, 'rb') as file:
		key_val = file.read(1)
		while key_val:
			if (pyversion < 3):
				key_scramble_data.append(binascii.hexlify(key_val))
			else:
				key_scramble_data.append(format(int.from_bytes(key_val, "big"), '02X'))
			key_val = file.read(1)
		print ("KEY SCRAMBLE[0]: 0x" + key_scramble_data[0].upper() + \
					       key_scramble_data[1].upper() + \
					       key_scramble_data[2].upper() + \
					       key_scramble_data[3].upper())
	pass

#
# Prints Key Scramble align, to be burned in the chip, on the screen
#
def print_key_scramble_align(key_scramble_align):
	'''
	Prints Key Scramble align, to be burned in the chip, on the screen
	'''
	print ("Burn Key Scramble Align as follows:")
	print ("KEY SCRAMBLE ALIGN[0]: 0x0000" + str(format(key_scramble_align, "02X")).upper() + "00")
	pass

#
# Prints OTFAD key, to be burned in the chip, on the screen
#
def print_otfad_key(otfad_key):
	'''
	Prints OTFAD key, to be burned in the chip, on the screen
	'''
	# Print OTFAD key in little-endian format as per OTFAD for burning the Fuse
	print ("Burn OTFAD key as follows:")

	i = OTFAD_KEY_SIZE - 1
	fuse_word = 0
	otfad_data = []
	with open(otfad_key, 'rb') as file:
		key_val = file.read(1)
		while key_val:
			if (pyversion < 3):
				otfad_data.append(binascii.hexlify(key_val))
			else:
				otfad_data.append(format(int.from_bytes(key_val, "big"), '02X'))
			key_val = file.read(1)
		while fuse_word <= 3:
			print ("OTFAD KEY[" + str(fuse_word) + "]: 0x" + otfad_data[i].upper() + \
									 otfad_data[i - 1].upper() + \
									 otfad_data[i - 2].upper() + \
									 otfad_data[i - 3].upper())
			fuse_word += 1
			i -= 4
	pass

#
# Usage text for the script
#
def print_usage():
	''' Usage text for the script '''
	print (YELLOW + "Usage: python build_otfad_enc_image.py <config_file_name>" + RESET)
	pass

#
# Concatenate required files into an output file (Only linux shell cmds supported)
#
def construct_final_image(part1, part2, part3, part4, file_name):
	''' Concatenate required files into an output file (Only linux shell cmds supported) '''

	shutil.move('header', res_path + 'header')
	try:
		subprocess.check_call('cat ' + res_path + 'header ' + part1.enc_image + ' ' \
								    + part2.enc_image + ' ' \
								    + part3.enc_image + ' ' \
								    + part4.enc_image + ' > ' + file_name, shell=True)
	except subprocess.CalledProcessError as e:
		print (RED + "Error: Encrypted Image concatenation failed : " + str(e.returncode) + RESET)
		sys.exit(1)
	except Exception as e:
		raise e
		sys.exit(1)

	# Concatenate key blobs
	try:
		subprocess.check_call('cat ' + part1.keyblob + ' ' \
					     + part2.keyblob + ' ' \
					     + part3.keyblob + ' ' \
					     + part4.keyblob + ' > ' + res_path + 'keyblobs', shell=True)
	except subprocess.CalledProcessError as e:
		print (RED + "Error: Keyblob concatenation failed : " + str(e.returncode) + RESET)
		sys.exit(1)
	except Exception as e:
		raise e
		sys.exit(1)

	# Insert Keyblobs into the encrypted image
	try:
		subprocess.check_call(["dd", "if=" + res_path + "keyblobs", \
					     "of=" + file_name, \
					     "count=256", \
					     "conv=notrunc", \
					     "status=none"])
	except subprocess.CalledProcessError as e:
		print (RED + "Error: dd command failed : " + str(e.returncode) + RESET)
		sys.exit(1)
	except Exception as e:
		raise e
		sys.exit(1)

	sys.stdout.write(GREEN)
	print (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	print ("OTFAD image created: " + file_name)
	print (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	sys.stdout.write(RESET)

	pass

#
# Generate OTFAD scrambled key
#
def generate_otfad_scrambled_key(otfad_key, key_scramble, key_scramble_align, context, scrambled_kek):
	''' Generate OTFAD scrambled key '''
	try:
		subprocess.check_call([KEY_SCRAMBLER_EXEC, \
					"-i", otfad_key, \
					"-k", key_scramble, \
					"-a", format(int(key_scramble_align), '02X'), \
					"-c", context, \
					"-o", scrambled_kek])
	except OSError:
		print (RED + "Error: Please re-build the Key Scrambler executable" + RESET)
		sys.exit(1)
	except Exception as e:
		raise e
		sys.exit(1)

	return scrambled_kek
	pass

#
# Wrap the Image encryption key with OTFAD key
#
def generate_keyblob(otfad_key, part1, part):
	''' Wrap the Image encryption key with OTFAD key '''
	if (part.en == 1):
		print (BLUE + "Generating Wrapped Image Encryption Key..." + RESET)
		try:
			subprocess.check_call([KEY_WRAP_EXEC, \
					"-i", otfad_key, \
					# "-r", part.enc_key, \
					# "-a", part.enc_key, \
					"-k", part.enc_key, \
					"-c", part.ctr, \
					"-s", hex(part.srt_addr), \
					"-e", hex(part.end_addr_kb), \
					"-v", \
					"-o", part.keyblob])
		except OSError:
			print (RED + "Error: Please re-build the Key Wrap executable" + RESET)
			sys.exit(1)
		except Exception as e:
			raise e
			sys.exit(1)
	else:
		print (YELLOW + "Generating Dummy Wrapped Image Encryption Key..." + RESET)
		try:
			subprocess.check_call([KEY_WRAP_EXEC, \
					"-i", otfad_key, \
					# "-r", part1.enc_key, \
					# "-a", part1.enc_key, \
					"-k", part1.enc_key, \
					"-c", part1.ctr, \
					"-s", hex(part1.srt_addr), \
					"-e", hex(part1.end_addr_kb), \
					"-o", part.keyblob])
		except OSError:
			print (RED + "Error: Please re-build the Key Wrap executable" + RESET)
			sys.exit(1)
		except Exception as e:
			raise e
			sys.exit(1)
	pass

#
# Encrypt the Input image with Image encryption key
#
def generate_encrypted_image(image, part):
	''' Encrypt the Input image with Image encryption key '''
	if (part.en == 1):
		print (BLUE + "Generating Encrypted Image..." + RESET)
		try:
			subprocess.check_call([ENCRYPT_IMAGE_EXEC, \
					"-i", image, \
					"-k", part.enc_key, \
					"-c", part.ctr, \
					"-s", hex(part.srt_addr), \
					"-e", hex(part.end_addr), \
					"-o", part.enc_image])
		except OSError:
			print (RED + "Error: Please re-build the Encrypt Image executable" + RESET)
			sys.exit(1)
		except Exception as e:
			raise e
			sys.exit(1)
	else:
		print (YELLOW + "Generating Dummy Encrypted Image..." + RESET)
		try:
			file = open(part.enc_image, FILE_WRITE)
		except Exception as e:
			raise e
			sys.exit(1)
		else:
			print ("Encrypted Image generated: " + part.enc_image)
			file.close()
	pass

#
# If image offset + size of subsequent boot image partition is equal to
# previous boot image partition, then reduce 1 byte (avoid overlap)
#
def evaluate_boot_part_length(part1, part2, part3, part4):
	'''
	If image offset + size of subsequent boot image partition is equal to
	previous boot image partition, then reduce 1 byte (avoid overlap)
	'''
	if (part2.en ==1 and (part1.offset + part1.size == part2.offset)):
		part1.end_addr_kb = part1.end_addr_kb - 1;
	if (part3.en ==1 and (part2.offset + part2.size == part3.offset)):
		part2.end_addr_kb = part2.end_addr_kb - 1;
	if (part4.en ==1 and (part3.offset + part3.size == part4.offset)):
		part3.end_addr_kb = part3.end_addr_kb - 1;
	pass

#
# Check whether boot image partitions are enabled serially not randomly
#
def validate_enabled_partitions(part1, part2, part3, part4):
	''' Check whether boot image partitions are enabled serially not randomly '''
	if (part4.en == 1 and (part3.en == 0 or part2.en == 0) or \
	    part3.en == 1 and part2.en == 0):
		print (RED + "Error: Boot image partitions should be enabled serially" + RESET)
		sys.exit(1)
	pass

#
# Check if at least one boot image partition is enabled. Also if all the
# input parameters of each boot image partitions are present
#
def check_min_param(param1, param2, param3, param4, part_num):
	'''
	Check if at least one boot image partition is enabled. Also if all the
	input parameters of each boot image partitions are present
	'''
	if (param1 == None and param2 == None and \
	    param3 == None and param4 == None):
		if (part_num == PART_NUM_1):
			print (RED + "Error: Atleast boot image partition 1 parameters needed" + RESET)
			sys.exit(1)
		else:
			return False
	elif (param1 == None or param2 == None or \
	      param3 == None or param4 == None):
		print (RED + "Error: Boot image " + str(part_num) + " parameters missing" + RESET)
		sys.exit(1)
	else:
		return True
	pass

#
# Check if total size of boot image partitions is not more than size of input
# image
#
def validate_input_image_size(file_name, part1, part2, part3, part4):
	'''
	Check if total size of boot image partitions is not more than size of input
	image
	'''
	statinfo = os.stat(file_name)

	if (part4.en == 1 and (part4.offset + part4.size > statinfo.st_size)):
		print ("Error : Boot image partition 4: Image offset and Size not aligned")
		sys.exit(1)
	elif (part3.en == 1 and (part3.offset + part3.size > statinfo.st_size)):
		print ("Error : Boot image partition 3: Image offset and Size not aligned")
		sys.exit(1)
	elif (part2.en == 1 and (part2.offset + part2.size > statinfo.st_size)):
		print ("Error : Boot image partition 2: Image offset and Size not aligned")
		sys.exit(1)
	elif (part1.en == 1 and (part1.offset + part1.size > statinfo.st_size)):
		print ("Error : Boot image partition 1: Image offset and Size not aligned")
		sys.exit(1)
	pass

#
# Check if image offset + size of current boot image partition is less
# than the image offset of subsequent boot image partition (meaning there
# is not overlap)
#
def validate_img_offset_size(part1, part2, part3, part4):
	'''
	Check if image offset + size of current boot image partition is less
	than the image offset of subsequent boot image partition (meaning there
	is not overlap)
	'''
	if (part2.en == 1 and (part1.offset + part1.size > part2.offset)):
		print ("Error : Boot image partition 2: Image offset not aligned")
		sys.exit(1)
	if (part3.en == 1 and (part2.offset + part2.size > part3.offset)):
		print ("Error : Boot image partition 3: Image offset not aligned")
		sys.exit(1)
	if (part4.en == 1 and (part3.offset + part3.size > part4.offset)):
		print ("Error : Boot image partition 4: Image offset not aligned")
		sys.exit(1)
	pass

#
# Check if the input variable is an integer and not negative
#
def validate_int_input(key, value):
	''' Check if the input variable is an integer and not negative '''
	if (value != None):
		try:
			is_int = int(value)
			if is_int >= 0:
				pass
			else:
				print (RED + "Error: " + key + ": Value cannot be negative" + RESET)
				sys.exit(1)
		except ValueError:
			print (RED + "Error: " + key + ": Value is not an integer" + RESET)
			sys.exit(1)
	pass

#
# Check if the input file exists
#
def check_file_exists(file_name):
	''' Check if the input file exists '''
	try:
		file = open(file_name, FILE_READ)
	except IOError:
		print (RED + "Error: No such file or directory: '" + file_name +"'" + RESET)
		sys.exit(1)
	except Exception as e:
		raise e
		sys.exit(1)
	else:
		file.close()
	pass

#
# Check if the input file is not empty and is of size check_size
#
def validate_file_size(file_name, check_size):
	''' Check if the input file is not empty and is of size check_size '''
	if (file_name != None):
		check_file_exists(file_name)

		statinfo = os.stat(file_name)
		if (statinfo.st_size <= 0):
			print (RED + "Error: " + file_name + " is empty." + RESET)
			sys.exit(1)

		if (statinfo.st_size != check_size and check_size != 0):
			print (RED + "Error: " + file_name + " is not of size " + str(check_size) + " bytes" + RESET)
			sys.exit(1)
	pass

#
# Parse the boot image partitions
#
def parse_boot_img_parts(img_part, part_num):
	''' Parse the boot image partitions '''
	image_part_en = 0
	for (key, value) in img_part:
		if (key == "image_offset"):
			validate_int_input(key, value)
			img_offset = value
			continue
		elif (key == "size"):
			validate_int_input(key, value)
			size = value
			continue
		elif (key == "image_enc_key"):
			validate_file_size(value, ENC_KEY_SIZE)
			enc_key = value
			continue
		elif (key == "counter"):
			validate_file_size(value, CTR_SIZE)
			ctr = value
			continue
		else:
			print (key+": Invalid input configuration\n")
			sys.exit(1)

	if (check_min_param(img_offset, size, enc_key, ctr, part_num) == True):
		image_part_en = 1
		return img_offset, size, enc_key, ctr, image_part_en
	else:
		return 0, 0, None, None, image_part_en
	pass

#
# Process input configuration file containing necessary parameters
#
def process_config_file(config_file):
	''' Process input configuration file containing necessary parameters '''
	# Roll through the configuration file
	for (key, value) in config_file:
		if key == "otfad_key":
			if (value == None):
				print (RED + "Error: OTFAD key file required" + RESET)
				sys.exit(1)
			validate_file_size(value, OTFAD_KEY_SIZE)
			otfad_key = value

		elif key == "input_image":
			if (value == None):
				print (RED + "Error: Input image file required" + RESET)
				sys.exit(1)
			validate_file_size(value, NO_CHECK)
			input_image = value

		elif key == "key_scramble":
			if (value != None):
				validate_file_size(value, KEY_SCRAMBLE_SIZE)
			key_scramble = value

		elif key == "key_scramble_align":
			if (value != None and value > 255):
				print (RED + "Error: Key scramble align value can be max 0xFF" + RESET)
			key_scramble_align = value

		elif key == "output_file":
			if (value == None):
				print (RED + "Error: Output image file required" + RESET)
				sys.exit(1)
			output_file = res_path + value

		elif key == "boot_image_part1":
			img_offset, size, enc_key, ctr, part_en = parse_boot_img_parts(value.items(), PART_NUM_1)
			part1 = boot_image_part(img_offset, size, enc_key, ctr, part_en, PART_NUM_1)

		elif key == "boot_image_part2":
			img_offset, size, enc_key, ctr, part_en = parse_boot_img_parts(value.items(), PART_NUM_2)
			part2 = boot_image_part(img_offset, size, enc_key, ctr, part_en, PART_NUM_2)

		elif key == "boot_image_part3":
			img_offset, size, enc_key, ctr, part_en = parse_boot_img_parts(value.items(), PART_NUM_3)
			part3 = boot_image_part(img_offset, size, enc_key, ctr, part_en, PART_NUM_3)

		elif key == "boot_image_part4":
			img_offset, size, enc_key, ctr, part_en = parse_boot_img_parts(value.items(), PART_NUM_4)
			part4 = boot_image_part(img_offset, size, enc_key, ctr, part_en, PART_NUM_4)

		else:
			sys.exit("invalid input configuration\n")

	validate_enabled_partitions(part1, part2, part3, part4)

	validate_img_offset_size(part1, part2, part3, part4)

	validate_input_image_size(input_image, part1, part2, part3, part4)

	evaluate_boot_part_length(part1, part2, part3, part4)

	for part in [part1, part2, part3, part4]:
		# Generate OTFAD scrambled key only when both key scramble and key scramble align are configured
		if (key_scramble != None and key_scramble_align != None):
			print (BLUE + "Generating OTFAD Scrambled key..." + RESET)
			# Context (part number) ranges from 0 - 3
			otfad_scrambled_key = generate_otfad_scrambled_key(otfad_key, \
									   key_scramble, \
									   str(key_scramble_align), \
									   str(part.num - 1), \
									   part.scrambled_kek)
			print ("Done!")
		else:
			otfad_scrambled_key = otfad_key

		generate_keyblob(otfad_scrambled_key, part1, part)
		print ("Done!")
		generate_encrypted_image(input_image, part)
		print ("Done!")

# TODO: inbetween images

	print (BLUE + "Assembling keyblobs and encrypted image..." + RESET)
	construct_final_image(part1, part2, part3, part4, output_file)
	print ("Done!")

	sys.stdout.write(CYAN)
	print ("Printing OTFAD key...")
	print_otfad_key(otfad_key)
	sys.stdout.write(RESET)

	if (key_scramble != None and key_scramble_align != None):
		sys.stdout.write(CYAN)
		print ("\nPrinting Key Scramble and Key Scramble Align...")
		print_key_scramble(key_scramble)
		print_key_scramble_align(key_scramble_align)
		sys.stdout.write(RESET)

	pass

def main(argv):
	sys.stdout.write(RESET)
	# Validate number of arguments
	if len(argv) != MAX_ARGS:
		print (RED + "Error: Invalid number of arguments" + RESET)
		print_usage()
		sys.exit(1)

	if (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
		print_usage()
		sys.exit(1)

	# Input config file
	config_file = sys.argv[1]

	# Load configuration file
	try:
		file = open(config_file, FILE_READ)
	except IOError:
		print (RED + "Error: No such file or directory: '" + config_file +"'" + RESET)
		sys.exit(1)
	except Exception as e:
		raise
	else:
		cfg = yaml.load(file, Loader=yaml.SafeLoader)
		# More on Loader: https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
		file.close()
		pass

	process_config_file(cfg.items())

	pass


pyversion = sys.version_info[0]

# Constants
FILE_READ = 'r'
FILE_WRITE = 'w'
MAX_ARGS = 2
PART_NUM_1 = 1
PART_NUM_2 = 2
PART_NUM_3 = 3
PART_NUM_4 = 4
NO_CHECK = 0
ENC_KEY_SIZE = 16
OTFAD_KEY_SIZE = 16
CTR_SIZE = 8
KEY_SCRAMBLE_SIZE = 4
MX7ULP_QSPI_BASE_ADDR = 0xC0000000
END_ADDR_RSVD = 0x3ff
SYS_PLATFORM = sys.platform

# Executable based on platform
if (SYS_PLATFORM == "cygwin" or SYS_PLATFORM == "win32"):
	KEY_SCRAMBLER_EXEC = "./key_scrambler/key_scrambler.exe"
	KEY_WRAP_EXEC = "./key_wrap/key_wrap.exe"
	ENCRYPT_IMAGE_EXEC = "./encrypt_image/encrypt_image.exe"
elif (SYS_PLATFORM == "linux" or SYS_PLATFORM == "linux2"):
	KEY_SCRAMBLER_EXEC = "./key_scrambler/key_scrambler"
	KEY_WRAP_EXEC = "./key_wrap/key_wrap"
	ENCRYPT_IMAGE_EXEC = "./encrypt_image/encrypt_image"
else:
	print ("Operating system not supported")
	sys.exit(1)

# Colors
if (SYS_PLATFORM != "win32"):
	RED   = "\033[1;31m"
	BLUE  = "\033[1;34m"
	CYAN  = "\033[1;36m"
	GREEN = "\033[0;32m"
	YELLOW = "\033[33m"
	RESET = "\033[0;0m"
else:
	RED   = ""
	BLUE  = ""
	CYAN  = ""
	GREEN = ""
	YELLOW = ""
	RESET = ""

# Delete and Create output result folder
res_path = "./result"
try:
	shutil.rmtree(res_path)
except OSError:
	print ("Deletion of the result directory %s failed" % res_path)

try:
	os.mkdir(res_path)
except OSError:
	print ("Creation of the result directory %s failed" % res_path)
	sys.exit(1)
except Exception as e:
	raise e
	sys.exit(1)

res_path = res_path + "/"

OTFAD_SCRAMBLED_KEY_FILE = res_path + "otfad_scrambled_key"

# Main function
if __name__ == '__main__':
	main(sys.argv)
