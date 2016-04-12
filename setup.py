from setuptools import find_packages, setup


setup(
    name='ewp',
    version='0.1.0',
    packages=find_packages(),
    author='Nathan Osman',
    author_email='nathan@quickmediasolutions.com',
    description="Support for PayPal's Encrypted Website Payments",
    license='MIT',
    url='https://github.com/nathan-osman/python-ewp',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
