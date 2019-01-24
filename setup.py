from setuptools import setup, find_packages

setup(name='Murpy',
      version='1.0',
      description='Mumble Server Framework',
      author='Ian Ling',
      include_package_data=True,
      packages=find_packages(),
      install_requires=['opuslib', 'pycryptodome', 'protobuf']
      )
