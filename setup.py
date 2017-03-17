from setuptools import Extension, setup


setup(
    name='ewp',
    version='0.1.1',
    ext_modules=[Extension(
        'ewp',
        sources=['src/ewp.c'],
        include_dirs=[
            '/usr/local/opt/openssl/include',  # macOS
        ],
        libraries=['crypto', 'ssl'],
        library_dirs=[
            '/usr/local/opt/openssl/lib',  # macOS
        ],
    )],
    test_suite='tests',
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
