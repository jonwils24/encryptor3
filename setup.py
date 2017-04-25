from setuptools import setup, find_packages

README = "README.md"

setup(
    name="encryptor",
    version='0.2',
    description='AWS File Encryptor',
    url='https://github.com/jonwils24/encryptor',
    author='Jonathan Wilson',
    author_email='wilsonwjonathan@gmail.com',
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