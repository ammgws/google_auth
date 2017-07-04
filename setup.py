from setuptools import setup
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='google_auth',
    version='0.1.0',
    description='Class for authenticating with Google',
    long_description=long_description,
    url='https://github.com/ammgws/google_auth',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=3.6',
    py_modules=['google_auth'],
    install_requires=['requests'],
)
