from setuptools import setup, find_packages

README = "README.md"

setup(
    name="encryptor",
    version='0.1',
    description='AWS File Encryptor',
    long_description=open(README).read(),
    url='https://github.com/jonwils24/encryptor',
    author='Jonathan Wilson',
    py_modules=['encryptor'],
    packages=find_packages(),
    install_requires=[
        'click',
        'boto3',
        'pycrypto'
    ],
    entry_points='''
        [console_scripts]
        encryptor=encryptor:cli
    ''',
)