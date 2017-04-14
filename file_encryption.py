#!/usr/local/bin/python

import os
import boto3
import base64
import argparse
import json
import ast
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
        plaintext = json.dumps(ast.literal_eval(fo.read()))
    return encrypt(plaintext, key)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

 
class AWS_Encrypted_File_Manager:

    def __init__(self, region, kms_key):
        self.region = region
        self.kms_key = kms_key
        self.s3 = boto3.client('s3', region)
        self.kms = boto3.client('kms', region)

    def generate_kms_keys(self):
        data_key_req =  self.kms.generate_data_key(
            KeyId=self.kms_key,
            KeySpec='AES_256'
        )

        return data_key_req['Plaintext'], data_key_req['CiphertextBlob']

    def encrypt_and_upload(self, filepath, bucket, filename):
        data_key, data_key_ciphered = self.generate_kms_keys()
        self.upload_s3(
            bucket,
            encrypt_file(filepath, data_key), 
            filename,
            data_key_ciphered
        )

    def upload_s3(self, bucket, encrypted_file, filename, cipher):
        self.s3.put_object(
            Bucket=bucket,
            Body=encrypted_file,
            Key=filename,
            Metadata={
                'encryption-key': base64.b64encode(cipher)
            }
        )

    def download_and_decrypt(self, bucket, filename):
        encrypted_file = self.s3.get_object(
            Bucket=bucket,
            Key=filename
        )

        data_key_ciphered = base64.b64decode(
            encrypted_file['Metadata']['encryption-key'])

        data_key = self.kms.decrypt(
            CiphertextBlob=data_key_ciphered)['Plaintext']


        self.bucket = bucket
        self.filename = filename
        self.__info = ast.literal_eval(
            decrypt(
                encrypted_file['Body'].read(), 
                data_key
            )
        )


    def get_file_content(self):
        s3 = boto3.resource('s3', self.region)
        content_object = s3.Object(self.bucket, self.filename)
        return ast.literal_eval(
            decrypt(content_object.get()['Body'].read(), self.data_key))

    def get_file(self, bucket, filename):
        file = self.s3.get_object(Bucket=bucket, Key=filename)
        self.__info = ast.literal_eval(decrypt(file['Body'].read(), self.data_key))
        return self.__info

    def get(self, key, default_value=None):
        try:
            self.__info
        except AttributeError as e:
            self.download_and_decrypt()
        try:
            return self.__info[key]
        except AttributeError as e:
            if default_value:
                return default_value
            else:
                raise

    def put(self, key, value):
        try:
            self.__info
        except AttributeError as e:
            self.download_and_decrypt()

        self.__info[key] = value
        data_key, data_key_ciphered = self.generate_kms_keys()
        self.upload_s3(
            self.bucket,
            encrypt(json.dumps(self.__info), data_key), 
            self.filename,
            data_key_ciphered
        )
        
        return {key: value}



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

