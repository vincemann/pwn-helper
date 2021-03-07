from setuptools import find_packages, setup

setup(
    name='pwnhelper',
    packages=find_packages(include=['pwnhelper']),
    version='0.1.0',
    description='helper lib for pwntools',
    author='vincemann',
    license='MIT',
    install_requires=['pwntools >= 4.3.1'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)