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


class AWS_Encryptor:

    def __init__(self, region, project, bucket=None, filename="env"):
        self.region = region
        self.project = project
        self.bucket = bucket
        self.filename = filename
        self.s3 = boto3.client('s3', region)
        self.kms = boto3.client('kms', region)

    def __get_kms_key(self):
        r = kms.list_aliases()
        search_name = 'alias/' + self.project
        try:
            [kms_key] = [str(x['TargetKeyId']
                             for x in r['Aliases'] 
                             if search_name == x['AliasName'])]
        except ValueError as e:
            key = kms.create_key()
            kms_key = str(key['KeyMetaData']['KeyId'])
            kms.create_alias(
                AliasName='alias/' + project,
                TargetKeyId=kms_key
            )
        return kms_key

    def __generate_kms_keys(self):
        data_key_req = self.kms.generate_data_key(
            KeyId=self.__get_kms_key,
            KeySpec='AES_256'
        )

        return data_key_req['Plaintext'], data_key_req['CiphertextBlob']

    def encrypt_and_upload(self, filepath, bucket=self.bucket):
        data_key, data_key_ciphered = self.__generate_kms_keys()
        self.__upload_s3(
            bucket,
            encrypt_file(filepath, data_key),
            filepath.rsplit('/')[-1],
            data_key_ciphered
        )

    def __upload_s3(self, bucket, encrypted_file, filename=self.filename, cipher):
        self.s3.put_object(
            Bucket=bucket,
            Body=encrypted_file,
            Key="{}-{}".format(filename, self.project),
            Metadata={
                'encryption-key': base64.b64encode(cipher)
            }
        )

    def download_and_decrypt(self, filename=self.filename, bucket=self.bucket):
        try:
            encrypted_file = self.s3.get_object(
                Bucket=bucket,
                Key=filename
            )
        except TypeError as e:
            encrypted_file = self.s3.get_object(
                Bucket=bucket,
                Key="{}-{}".format(filename, self.project)
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
        data_key, data_key_ciphered = self.__generate_kms_keys()
        self.__upload_s3(
            self.bucket,
            encrypt(json.dumps(self.__info), data_key),
            self.filename,
            data_key_ciphered
        )

        return value


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

        kms = boto3.client('kms', args.region)  # DO NOT hardcode region
        data_key_req = kms.generate_data_key(
            KeyId='b1558cc7-fc6a-4131-9d43-cc830f165ba4',  # DO NOT hardcode KeyId
            KeySpec='AES_256'
        )
        data_key = data_key_req['Plaintext']
        data_key_ciphered = data_key_req['CiphertextBlob']

        encrypt_file(filepath, data_key)
        encrypted_filename = filename + '.enc'
        encrypted_filepath = './upload_file/' + encrypted_filename

        s3 = boto3.client('s3', args.region)  # DO NOT hardcode region
        s3.put_object(
            Bucket=args.bucket,  # DO NOT hardcode bucket name
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
