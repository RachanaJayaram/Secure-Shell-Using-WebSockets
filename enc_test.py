from Crypto.Cipher import AES
import base64, os

def decrypt_message(encoded_encrypted_msg, encoded_secret_key, padding_character):
	# decode the encoded encrypted message and encoded secret key
	secret_key = base64.b64decode(encoded_secret_key)
	encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	# use the decoded secret key to create a AES cipher
	cipher = AES.new(secret_key)
	# use the cipher to decrypt the encrypted message
	decrypted_msg = cipher.decrypt(encrypted_msg)
	# unpad the encrypted message
	unpadded_private_msg = decrypted_msg.rstrip(padding_character)
	# return a decrypted original private message
	return unpadded_private_msg     