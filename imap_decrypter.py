#!/usr/bin/python

'''
IMAP mass decrypter by @cielavenir

Basic idea is from Enigmail's "create decrypted copy" filter (https://enigmail.net/).
'''

import sys
import os
import json
import imaplib
import email
import re
import base64
import quopri

import subprocess
import signal
import time
from contextlib import contextmanager

def StopProcs(procs, seconds=5):
    for proc in procs:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
    for _ in range(int(seconds*100*0.8)):
        if all(proc.poll() is not None for proc in procs):
            return
        time.sleep(0.01)
    for proc in procs:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    for _ in range(int(seconds*100*0.2)):
        if all(proc.poll() is not None for proc in procs):
            return
        time.sleep(0.01)
    for proc in procs:
        if proc.poll() is None:
            proc.send_signal(signal.SIGKILL)
            proc.wait()

@contextmanager
def CheckPopen(args, **kwargs):
    '''
    context manager version of Popen.

    1. Context manager is not available in Python2.
    2. When exceptions happened in Python3 original context, the process might get stuck especially when the process is daemon.
       We try to kill the process implicitly when exception happens.
    3. Not closing stdin/stdout implicitly to make sure we communicate with the pipe correctly.
    '''

    proc = subprocess.Popen(args, **kwargs)
    exc_type = None
    try:
        yield proc
    except Exception:
        exc_type = sys.exc_info()[0]
        raise
    finally:
        if exc_type is not None:
            StopProcs([proc])
        elif proc.wait():
            raise subprocess.CalledProcessError(proc.returncode, args)

def _Fold(msg):
    return re.sub("(.{1,72})","\\1\r\n",msg)

def _SetHeader(part, name, value):
    if name in part:
        part.replace_header(name,value)
    else:
        part.add_header(name,value)

def _DecryptPart(part):
    '''
    decrypts mail part.

    :param part: email part
    :type part: email.message.Message
    :returns: True -> decrypted, False -> decryption failed, None -> decryption not required
    :rtype: bool
    '''

    if part.is_multipart():
        decrypted = False
        for e in part.get_payload():
            res = _DecryptPart(e)
            if res is False:
                return False
            elif res is True and not decrypted:
                decrypted = True
        if decrypted:
            return True
        return None
            
    body = part.get_payload()
    needEncodingPayload = False
    if part['content-transfer-encoding'] is not None:
        if part['content-transfer-encoding'].lower() == 'base64':
            needEncodingPayload = False
            body = base64.b64decode(body)
        elif part['content-transfer-encoding'].lower() == 'quoted-printable':
            needEncodingPayload = True
            body = quopri.decodestring(body)

    ### body might not be armored
    ### todo: what if unarmored public key is sent? gpg will fail...
    armor_pgp_header_bytes = b'-----BEGIN PGP MESSAGE-----'
    armor_pgp_header_str = b'-----BEGIN PGP MESSAGE-----'
    if (len(body)>3 and ord(body[:1])==133 and ord(body[3:4])==3) or body[:len(armor_pgp_header_bytes)] == armor_pgp_header_bytes or body[:len(armor_pgp_header_str)] == armor_pgp_header_str:
        ### in some cases like gpg-mailing list, double-encryption can happen.
        ### but we decrypt only once to avoid the situation that mail body successfully decrypted but attachment decryption fails.
        filename = part.get_filename()
        if filename is not None:
            filename = re.sub("\.(gpg|pgp|asc)$","",filename)
            ### unlike enigmail, we are not going to use gpg-embedded filename.
            ### further note: filenames like "-&1" are gpg special filename and must be discarded.
            if part.get_param('name',header='content-type') is not None:
                part.set_param('name',filename,header='content-type')
            if part.get_param('filename',header='content-disposition') is not None:
                part.set_param('filename',filename,header='content-disposition')
        err = ''
        try:
            with CheckPopen(['gpg','--decrypt','--skip-verify'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as proc:
                out, err = proc.communicate(body)
                if re.search(b"[^\x01-\x7f]",out) or needEncodingPayload:
                    _SetHeader(part,'content-transfer-encoding','base64')
                    part.set_payload(_Fold(base64.b64encode(out).decode('utf-8')))
                else:
                    part.set_payload(out)
        except subprocess.CalledProcessError:
            sys.stderr.write(err.decode('utf-8'))
            sys.stderr.write("\n")
            return False
        return True
    return None

def DecryptAll(msg, copy_unencrypted=False):
    '''
    decrypts mail whole.

    :param msg: email string
    :type msg: Py2 -> str, Py3 -> bytes
    :param copy_unencrypted: specifies whether to copy email even unencrypted
    :type copy_unencrypted: bool
    :returns: new email string or None if decryption fails (or unencrypted)
    :rtype: Py2 -> str, Py3 -> bytes
    '''

    decrypted = False
    if sys.version_info[0]>=3:
        mail = email.message_from_bytes(msg)
    else:
        mail = email.message_from_string(msg)
    sys.stderr.write('Processing: '+str(mail['subject'])+"\n")
    if mail.get_content_type() == 'multipart/encrypted':
        # PGP/MIME, which should be armored
        err = ''
        try:
            with CheckPopen(['gpg','--decrypt','--skip-verify'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as proc:
                out, err = proc.communicate(mail.get_payload()[1].get_payload().encode('utf-8'))
            if sys.version_info[0]>=3:
                pgpmime_decrypted = email.message_from_bytes(out)
            else:
                pgpmime_decrypted = email.message_from_string(out)
            # copy header
            for k,v in mail.items():
                if k.lower()!='mime-version' and k not in pgpmime_decrypted:
                    pgpmime_decrypted[k] = v
            if pgpmime_decrypted.is_multipart():
                pgpmime_decrypted['MIME-Version'] = mail['MIME-Version'] or '1.0'
            decrypted = True
            mail = pgpmime_decrypted
        except subprocess.CalledProcessError:
            sys.stderr.write(err.decode('utf-8'))
            sys.stderr.write("\n")
            return None
    elif mail.is_multipart():
        for e in mail.get_payload():
            res = _DecryptPart(e)
            if res is False:
                return None # failed
            elif res is True and not decrypted:
                decrypted = True
    else:
        res = _DecryptPart(mail)
        if res is False:
            return None # failed
        elif res is True and not decrypted:
            decrypted = True
    if decrypted or copy_unencrypted:
        if sys.version_info[0]>=3:
            return mail.as_bytes()
        else:
            return mail.as_string()
    # unencrypted
    return None

if __name__ == '__main__':
    if not sys.stdin.isatty():
        if sys.version_info[0]>=3:
            msg = sys.stdin.buffer.read()
        else:
            msg = sys.stdin.read()
        print(DecryptAll(msg).decode('utf-8'))
        exit(0)

def DecryptBatch(server, port, user, password):
    imap = imaplib.IMAP4_SSL(server,port)
    imap.login(user,password)
    status, folders = imap.list()
    folders = [(re.search('"([^"]*)"$',e.decode('utf-8')) or re.search('([^\s]*)$',e.decode('utf-8'))).group(1) for e in folders]
    inboxes = [e for e in folders if e.lower()=='inbox' or e.lower().startswith('inbox/') or e.lower()=='sent']
    for inbox in inboxes:
        sys.stderr.write('Opening folder: '+inbox+"\n")
        #if inbox!='INBOX':
        #    continue
        decbox = 'DECRYPT_'+inbox
        imap.create(decbox)

        status, _ = imap.select(inbox)
        status, maillst = imap.search(None, 'ALL')
        for num in maillst[0].split():
            status, data = imap.fetch(num, '(RFC822)')
            msg = data[0][1]
            msg = DecryptAll(msg)
            if msg is not None:
                imap.append(decbox,('\SEEN',),None,msg)
            #break
    imap.logout()

if __name__ == '__main__':
    if not sys.stdin.isatty():
        if sys.version_info[0]>=3:
            msg = sys.stdin.buffer.read()
        else:
            msg = sys.stdin.read()
        print(DecryptAll(msg).decode('utf-8'))
        exit(0)
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),'imap_decrypter.json')) as f:
        data = json.load(f)
    DecryptBatch(data['IMAP_SERVER'],data['IMAP_PORT'],data['IMAP_USER'],data['IMAP_PASSWORD'])
