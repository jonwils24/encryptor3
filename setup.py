from setuptools import setup, find_packages

README = "README.md"

setup(
    name="encryptor3",
    version='0.5',
    description='AWS File Encryptor',
    url='https://github.com/jonwils24/encryptor3',
    author='Jonathan Wilson',
    author_email='wilsonwjonathan@gmail.com',
    py_modules=['encryptor3'],
    packages=find_packages(),
    install_requires=[
        'click',
        'boto3',
        'pycrypto'
    ],
    entry_points='''
        [console_scripts]
        encryptor3=encryptor3:cli
    ''',
)