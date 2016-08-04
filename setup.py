try:
    from setuptools import setup
except ImportError:
    fron distutils.core import setup

config = {
        'description': 'audit2json',
        'author': 'Orien Vandenbergh',
        'url': 'http://github.com/nichus/audit2json',
        'download_url': 'someplace',
        'author_email': "dunno",
        'version': '0.0.1',
        'install_requires': ['nose2'],
        'packages': ['audit2json'],
        'scripts': [],
        'name': 'audit2json'
}

setup(**config)
