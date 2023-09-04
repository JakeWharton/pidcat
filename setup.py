from setuptools import setup

from pidcat import __version__ 

setup(
    name='pidcat',
    version=__version__ ,
    description='Colored logcat script which only shows log entries for a specific application package.',
    author='JakeWharton',
    url='https://github.com/JamesConlan96/pidcat',
    license='Apache-2.0',
    py_modules=[
        'pidcat'
    ],
    python_requires='>=3.0.0',
    entry_points={
        'console_scripts': [
            'pidcat = pidcat:main'
        ]
    }
)