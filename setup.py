from setuptools import setup, find_packages

setup(
    name='santaHog',
    version='0.0.0',
    description='Searches through package revision history for secrets.',
    url='https://github.com/dxa4481/santaHog',
    author='Dylan Ayrey',
    author_email='dylanayrey@gmail.com',
    license='GNU',
    packages = ['santaHog'],
    install_requires=[
        'truffleHogRegexes == 0.0.4',
        'beautifulsoup4==4.6.0',
        'requests==2.18.4'
    ],
    entry_points = {
      'console_scripts': ['santahog = santaHog.santaHog:main'],
    },
)
