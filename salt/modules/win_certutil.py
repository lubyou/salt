# -*- coding: utf-8 -*-
'''
This module allows you to install certificates into the windows certificate
manager.

.. code-block:: bash

    salt '*' certutil.add_store salt://cert.cer "TrustedPublisher"
'''

# Import Python Libs
from __future__ import absolute_import
import re
import logging

# Import Salt Libs
import salt.utils

log = logging.getLogger(__name__)
__virtualname__ = "certutil"


def __virtual__():
    '''
    Only work on Windows
    '''
    if salt.utils.is_windows():
        return __virtualname__
    return False


def get_cert_serial(cert_file):
    '''
    Get the serial number of a certificate file

    cert_file
        The certificate file to find the serial for

    '''
    cmd = "certutil.exe -verify {0}".format(cert_file)
    out = __salt__['cmd.run'](cmd)

    """
    Émetteur:
        CN=Google Internet Authority G2
        O=Google Inc
        C=US
    Objet:
        CN=*.google.com
        O=Google Inc
        L=Mountain View
        S=California
        C=US
    Numéro de série du certificat : 76385ee42745b0cd
    """

    cn_count = 0
    for line in out.splitlines():
        line = line.strip()

        if not line:
            continue

        if "CN" in line:
            cn_count += 1

        elif cn_count > 2 and ":" in line:
            line = line.split()

            if len(line) == 2:
                serial = line[-1].strip()

                if serial:
                    return serial

    return None


def get_stored_cert_serials(store):
    '''
    Get all of the certificate serials in the specified store

    store
        The store to get all the certificate serials from

    '''
    cmd = "certutil.exe -store {0}".format(store)
    out = __salt__['cmd.run'](cmd)

    """
    Root
    ================ Certificat 0 ================
    Numéro de série : 79ad16a14aa0a5ad4c7358f407132e65
    Émetteur: CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com
     NotBefore : 10/05/2001 00:19
     NotAfter : 10/05/2021 00:28
    Objet: CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com
    Version de l’autorité de certification: V0.0
    La signature correspond à la clé publique
    Certificat racine : le sujet correspond à l’émetteur
    Modèle:
    Hach. cert. (sha1) : cd d4 ee ae 60 00 ac 7f 40 c3 80 2c 17 1e 30 14 80 30 c0 72
    Aucune information sur le fournisseur de clé
    Impossible de trouver le certificat et la clé privée pour le déchiffrement.

    ================ Certificat 1 ================
    Numéro de série : 00
    Émetteur: CN=Thawte Timestamping CA, OU=Thawte Certification, O=Thawte, L=Durbanville, S=Western Cape, C=ZA
     NotBefore : 01/01/1997 01:00
     NotAfter : 01/01/2021 00:59
    Objet: CN=Thawte Timestamping CA, OU=Thawte Certification, O=Thawte, L=Durbanville, S=Western Cape, C=ZA
    La signature correspond à la clé publique
    Certificat racine : le sujet correspond à l’émetteur
    Modèle:
    Hach. cert. (sha1) : be 36 a4 56 2f b2 ee 05 db b3 d3 23 23 ad f4 45 08 4e d6 56
    Aucune information sur le fournisseur de clé
    Impossible de trouver le certificat et la clé privée pour le déchiffrement.
    """

    pattern = r"================.*================\n.*: (.*)\n.\w+.*:.*=.*"
    return re.findall(pattern, out)


def add_store(source, store, saltenv='base'):
    '''
    Add the given cert into the given Certificate Store

    source
        The source certificate file this can be in the form
        salt://path/to/file

    store
        The certificate store to add the certificate to

    saltenv
        The salt environment to use this is ignored if the path
        is local

    CLI Example:

    .. code-block:: bash

        salt '*' certutil.add_store salt://cert.cer TrustedPublisher
    '''
    cert_file = __salt__['cp.cache_file'](source, saltenv)
    cmd = "certutil.exe -addstore {0} {1}".format(store, cert_file)
    return __salt__['cmd.run'](cmd)


def del_store(source, store, saltenv='base'):
    '''
    Delete the given cert into the given Certificate Store

    source
        The source certificate file this can be in the form
        salt://path/to/file

    store
        The certificate store to delete the certificate from

    saltenv
        The salt environment to use this is ignored if the path
        is local

    CLI Example:

    .. code-block:: bash

        salt '*' certutil.del_store salt://cert.cer TrustedPublisher
    '''
    cert_file = __salt__['cp.cache_file'](source, saltenv)
    serial = get_cert_serial(cert_file)
    cmd = "certutil.exe -delstore {0} {1}".format(store, serial)
    return __salt__['cmd.run'](cmd)
