#! /usr/bin/env python2
"""
Krypton - a *super* experimental ASCII cipher from the planet Krypton

An effort to learn crypto BIG ideas:
1. Confusion - Caeser cipher 
2. Diffusion - Column transportation
3. Secret only in the key - As obvious as it is

http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
"""
import binascii
from itertools import izip, cycle
import optparse
import sys

def main():
    """ main command line user interactions
    """
    p = optparse.OptionParser();

    p.add_option("-D", action="store_true", dest="decrypt", default=False,
            help="Turn on the DeKryptonisation mode. Default is false.");

    p.add_option("-B", action="store_true", dest="binary", default=False,
            help="Turn on Binary mode. If the original data is non ascii.")

    p.add_option("-k", "--key", action="store", dest="key", metavar="key",
            help="The secret key to EnKryptonise or DeKryptonise with.")

    p.add_option("-d", "--data", action="store", dest="data", metavar="data",
            help="Data to EnKryptonise or to DeKryptonise.");

    p.add_option("-i", "--in", action="store", dest="infile", metavar="in",
            help="Input file to EnKryptonise or DeKryptonise.")

    p.add_option("-o", "--out", action="store", dest="outfile", metavar="out",
            help="Output file to put EnKryptonised or DeKryptonised data.")

    opts, args = p.parse_args();

    if opts.key and len(opts.key) > 0:
        key = opts.key;
    else:
        sys.exit("Yo you forgot the key?! Use -k or --key option to give the key.")

    infile = None
    outfile = None

    # Decrypt
    if opts.decrypt:
        if opts.infile:
            try:
                infile = open(opts.infile, "rb")
                _doMagic(infile) # Magic number check
                crypted = infile.read()
            except SystemExit, ex:
                sys.exit(ex)
            except:
                if infile:
                    infile.close()
                sys.exit("You may want to consider giving me some real filename.")
            finally:
                if infile:
                    infile.close()
        elif opts.data:
            crypted = binascii.unhexlify(opts.data)
        else:
            sys.exit("Oops.. Where is your EnKryptonised data?")

        if opts.outfile:
            try:
                if opts.binary:
                    outfile = open(opts.outfile, "wb")
                else:
                    outfile = open(opts.outfile, "w")

                data = DeKrypton(crypted, key)
                if opts.binary:
                    try:
                        data = binascii.unhexlify(data)
                    except:
                        outfile.close()
                        sys.exit("An error occured. Probably your secret key is not right! Check again...")
                outfile.write(data)
            except:
                if outfile:
                    outfile.close()
                sys.exit("I can't write to that file. Try another name.")
            finally:
                if outfile:
                    outfile.close()

        else:
            data = DeKrypton(crypted, key)
            if opts.binary:
                try:
                    data = binascii.unhexlify(data)
                except:
                    sys.exit("An error occured. Probably your secret key is not right! Check again...")
            print("D-Kryptonited:\n==============\n" + data)

    # Encrypt
    else:
        if opts.infile:
            try:
                if opts.binary:
                    infile = open(opts.infile, "rb")
                else:
                    infile = open(opts.infile, "r")

                data = infile.read()
            except IOError:
                sys.exit("You may want to consider giving me some real filename.")
            finally:
                if infile:
                    infile.close()

        elif opts.data:
            data = opts.data
        else:
            sys.exit("Oops.. Where is the data you wanna EnKryptonise?")
        
        if opts.binary:
            data = binascii.hexlify(data)

        if opts.outfile:
            try:
                outfile = open(opts.outfile, "wb")
                crypted = EnKrypton(data, key)
                _doMagic(outfile)
                outfile.write(crypted)
            except IOError as ex:
                sys.exit("Beeep... I can't write to that file name. Try another file name.")
            finally:
                if outfile:
                    outfile.close()
        else:
            crypted = EnKrypton(data, key)
            printable = binascii.hexlify(crypted)
            print("En-Kryptonised:\n===============\n" + printable) 

def EnKrypton(data, key):
    key_len =  len(key)
    key = _diffusion(key)
    confued = _confusion(data, key_len)
    crypted = _cryption(confued, key)
    return crypted

def DeKrypton(data, key):
    key_len = len(key)
    key = _diffusion(key)
    confued = _cryption(data, key)
    crypted = _deconfusion(confued, key_len)
    return crypted

def _confusion(data, extent):
    confused = []
    for ch in data:
        if (ord(ch) + extent) < 255:
            confused.append(chr(ord(ch) + extent))
        else:
            confused.append(chr(ord(ch) + extent - 255))

    return ''.join(confused)

def _deconfusion(data, extent):
    deconfused = []
    for ch in data:
            if (ord(ch) -  extent) > 0:
                deconfused.append(chr(ord(ch) - extent))
            else:
                deconfused.append(chr(ord(ch) - extent + 255))
                
    return ''.join(deconfused)

def _diffusion(key):
    """ Diffuse the key """
    # needs lot more improvement in terms of secure cryptography
    
    # chunk size
    SIZE = 16
    keychrs = [ch for ch in str(key)] 
    if len(key) % SIZE != 0:
        keychrs.extend([ch for ch in (str(key) * ((SIZE // len(key)) - 1))])
        keychrs.extend([ch for ch in (str(key)[:(SIZE - len(keychrs)%SIZE)])])
        
    expanded_key_length = len(keychrs)

    if expanded_key_length % SIZE != 0: 
        print expanded_key_length
        exit("Wrong algo")
    
    for i in xrange(0, expanded_key_length, SIZE):
        keychrs[i:i+SIZE] = reversed(keychrs[i:i+SIZE])

    return ''.join(keychrs)

def _cryption(data, key):
    """ Enc or Dec - XOR operation works both ways """
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))

def _doMagic(f):
    """
    Check or write the magic number according to the mode of open file.
    """
    themagic = "KRYPT"
    if f.mode.find("r") > -1:
        magic = f.read(5)
        if magic != themagic:
            exit("Are you sure that the file is a kryptonised file?")
    elif f.mode.find("w") > -1:
        f.write(themagic)

if __name__ == '__main__':
    main()
