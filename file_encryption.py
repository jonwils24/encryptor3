#!/usr/bin/python

import os
import boto3
import base64
import argparse
from Crypto import Random
from Crypto.Cipher import AES

pad = lambda s: s + (32 - len(s) % 32) * ' '

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('region')
    parser.add_argument('bucket')
    parser.add_argument('key')

    args = parser.parse_args()

    if args.action == "encrypt":
        filename = os.listdir('./upload_file')[0]
        filepath = './upload_file/' + filename

        kms = boto3.client('kms', args.region) # DO NOT hardcode region
        data_key_req = kms.generate_data_key(
            KeyId='b1558cc7-fc6a-4131-9d43-cc830f165ba4', # DO NOT hardcode KeyId
            KeySpec='AES_256'
        )
        data_key = data_key_req['Plaintext']
        data_key_ciphered = data_key_req['CiphertextBlob']

        encrypt_file(filepath, data_key)
        encrypted_filename = filename + '.enc'
        encrypted_filepath = './upload_file/' + encrypted_filename

        s3 = boto3.client('s3', args.region) # DO NOT hardcode region
        s3.put_object(
            Bucket=args.bucket, # DO NOT hardcode bucket name
            Body=open(encrypted_filepath, 'r'),
            Key=filename,
            Metadata={'encryption-key': base64.b64encode(data_key_ciphered)}
        )

    elif args.action == "decrypt":
        s3 = boto3.client('s3', args.region)
        file_obj = s3.get_object(
            Bucket=args.bucket,
            Key=args.key
        )

        data_key_ciphered = base64.b64decode(
            file_obj['Metadata']['encryption-key'])

        kms = boto3.client('kms', args.region)
        data_key = kms.decrypt(CiphertextBlob=data_key_ciphered)['Plaintext']

        s3 = boto3.resource('s3', args.region)
        s3.meta.client.download_file(
            args.bucket, args.key, './downloaded_file/{}.enc'.format(args.key))

        decrypt_file('./downloaded_file/{}.enc'.format(args.key), data_key)

if __name__ == "__main__":
    main()

