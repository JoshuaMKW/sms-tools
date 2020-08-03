import os
import re
import sys
import struct
import binascii
import argparse
import glob

from io import BytesIO, RawIOBase

def wrap_text(string, comment=False):
    if comment == False:
        return '-'*(len(string) + 2) + '\n|' + string + '|\n' + '-'*(len(string) + 2)
    else:
        return '#' + '-'*(len(string) + 2) + '#' + '\n# ' + string + ' #\n' + '#' + '-'*(len(string) + 2) + '#'

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def get_size(file, offset=0):
    """ Return a file's size """
    file.seek(0, 2)
    return file.tell() + offset

def getFileAlignment(file, alignment):
    """ Return file alignment, 0 = aligned, non zero = misaligned """
    size = get_size(file)

    if size % alignment != 0:
        return alignment - (size % alignment)
    else:
        return 0

def alignFile(file, alignment, char='00'):
    """ Align a file to be the specified size """
    file.write(bytes.fromhex(char * getFileAlignment(file, alignment)))

def byte2bool(byte: str):
    if byte == b'\x01':
        return "True"
    else:
        return "False"

def bool2byte(string: str):
    if string == 'True':
        return b'\x01'
    else:
        return b'\x00'

def get_parent(string: str):
    return re.findall(r'(?:[a-zA-Z_])[\w\s]+(?=\s*[<0-9>]*=)', string)[0].strip()

def get_value_size_key(string: str):
    return int(re.findall(r'(?:\s*<)([0-9]+)(?=>\s*=)', string)[0].strip())

def get_all_key(string: str):
    return re.findall(r'(?:=\s*)([\w\s\-.,]*)', string)[0].strip()

def get_hex_key(string: str, byteslength=None):
    try:
        key = re.findall(r'(?:=\s*)(0x[0-9a-fA-F\-]+)(?=;)', string)[0]
        if byteslength is not None:
            key = '0x' + '{:08X}'.format(int(key[2:], 16))[8 - (byteslength << 1):]
        return key.strip()
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper hexadecimal'.format(get_all_key(string), get_parent(string)))

def get_float_key(string: str):
    try:
        return float(re.findall(r'(?:=\s*)([0-9\-.]+)(?=;)', string)[0].strip())
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper float'.format(get_all_key(string), get_parent(string)))

def get_int_key(string: str):
    try:
        return int(re.findall(r'(?:=\s*)([0-9\-]+)(?=;)', string)[0].strip())
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper int'.format(get_all_key(string), get_parent(string)))

def get_bool_key(string: str):
    try:
        return re.findall(r'(?:=\s*)(True|False|true|false)(?=;)', string)[0].strip()
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper boolean'.format(get_all_key(string), get_parent(string)))

def get_tuple_key(string: str):
    try:
        keys = re.findall(r'(?:=\s*\(\s*)([\w\s\-.,]+)(?=\s*\);)', string)[0]
        keys = keys.split(',')
        for i, key in enumerate(keys):
            keys[i] = key.strip()
        return tuple(keys)
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper tuple'.format(get_all_key(string), get_parent(string)))

def get_list_key(string: str):
    try:
        keys = re.findall(r'(?:=\s*\[\s*)([\w\s\-.,]+)(?=\s*\];)', string)[0]
        keys = keys.split(',')
        for i, key in enumerate(keys):
            keys[i] = key.strip()
        return list(keys)
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper list'.format(get_all_key(string), get_parent(string)))

def get_string_key(string: str):
    try:
        return str(re.findall(r'(?:=\s*\")([\s\w.\-\/!?]+)(?=\";)', string)[0])
    except IndexError:
        parser.error('Value "{}" at key "{}" is not a proper string'.format(get_all_key(string), get_parent(string)))

def safe_write_value(file, value, size=1, byteorder='big', signed=False, allowfloat=True):
    if allowfloat == True:
        if '(' in value or ')' in value or '[' in value or ']' in value:
            parser.error('Value "{}" at key "{}" is not int or hexadecimal or float'.format(get_all_key(value), get_parent(value)))
    else:
        if '.' in value or '(' in value or ')' in value or '[' in value or ']' in value:
            parser.error('Value "{}" at key "{}" is not int or hexadecimal'.format(get_all_key(value), get_parent(value)))
    if '0x' in value:
        if len(value[2:]) < (size << 1):
            value = '0x' + ('0'*((size << 1) - len(value[2:]))) + value[2:]
        file.write(bytes.fromhex(value[2:]))
    elif '.' in value:
        file.write(struct.pack('>f', float(value)))
    else:
        file.write(int(value).to_bytes(size, byteorder=byteorder, signed=signed))

def calc_key_code(key: str):
    context = 0
    for char in key:
        context = ord(char) + (context * 3)
        if context > 0xFFFFFFFF:
            context -= 0x100000000
    return '{:04X}'.format(context & 0xFFFF)

class PrmFile():

    def __init__(self, f):
        self.rawdata = BytesIO(f.read())
        f.seek(0)
        self.totalSections = int.from_bytes(f.read(4), byteorder='big', signed=False)
        self.sections = {}
        
        i = 0
        while i < self.totalSections:
            hashkey = f.read(2).hex()
            stringlen = int.from_bytes(f.read(2), byteorder='big', signed=False)
            string = f.read(stringlen).decode('utf-8')
            valuelength = int.from_bytes(f.read(4), byteorder='big', signed=False)
            value = f.read(valuelength)
            self.sections[string] = [hashkey, stringlen, valuelength, value]
            i += 1

    def get_attributes(self, key: str):
        return self.sections.get(key)

    def set_attributes(self, key: str, valuelength: int, value: bytes):
        self.sections.update({key: [calc_key_code(key), len(key), valuelength, value]})
    
    def edit_value(self, key: str, value: bytes):
        length = self.get_attributes(key)[2]
        valuelen = len(value)
        if valuelen > length:
            value = value[valuelen - length:]
        elif valuelen < length:
            value = b'\x00'*(length - valuelen) + value
        if valuelen > 4:
            value = value[valuelen - 4:]
        self.sections[key][3] = value
    
    def load_attributes(self, outputfile):
        outputfile.write(wrap_text('PRM', True) + '\n\n#Entries follow the format <key> <size>= <value>, key can be any non whitespace name you want.\n\n')
        for key in self.sections.keys():
            outputfile.write('{} <{}>=\t'.format(key.ljust(24), self.get_attributes(key)[2]) + '0x{};\n'.format(self.get_attributes(key)[3].hex().upper()))

def load_params(file, dest=None, considerfolder=False):
    if dest is None:
        dest = os.path.abspath(os.path.normpath(os.path.splitext(file)[0].lstrip('\\').lstrip('/') + '.txt'))
    elif considerfolder:
        dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(file)[0] + '.txt'))
    
    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))
    
    with open(file, 'rb') as prm:
        prmfile = PrmFile(prm)

    with open(dest, 'w+') as dump:
        prmfile.load_attributes(dump)
    

def save_params(file, dest=None, obeyPrevAttrs=True, considerfolder=False):
    if dest is None:
        dest = os.path.abspath(os.path.normpath(os.path.splitext(file)[0].lstrip('\\').lstrip('/') + '.prm'))
    elif considerfolder:
        dest = os.path.join(os.path.abspath(os.path.normpath(os.path.splitext(dest)[0].lstrip('\\').lstrip('/'))), os.path.basename(os.path.splitext(file)[0] + '.prm'))
    
    if not os.path.exists(os.path.dirname(dest)) and os.path.dirname(dest) not in ('', '/'):
        os.makedirs(os.path.dirname(dest))

    try:
        with open(dest, 'rb') as prm:
            prmfile = PrmFile(prm)
    except FileNotFoundError:
        prmfile = None

    with open(file, 'r') as txtfile, open(dest, 'wb+') as dump:
        dump.write(b'\x00\x00\x00\x00')
        i = 0

        if prmfile is None or obeyPrevAttrs == False:
            for line in txtfile.readlines():
                if line.strip().startswith('#') or line == '' or line == '\n':
                    continue

                key = get_parent(line)
                value = get_all_key(line)
                size = get_value_size_key(line)
                
                if '.' in value:
                    value = struct.pack('>f', float(value))
                elif value.startswith('0x'):
                    value = int(value, 16).to_bytes(size, 'big', signed=False)
                else:
                    value = int(value).to_bytes(size, 'big', signed=False)

                dump.write(bytes.fromhex(calc_key_code(key)) +
                           len(key).to_bytes(2, 'big', signed=False) +
                           key.encode('utf-8') +
                           size.to_bytes(4, 'big', signed=False) +
                           value)

                i += 1
        else:
            for line in txtfile.readlines():
                if line.strip().startswith('#') or line == '' or line == '\n':
                    continue

                key = get_parent(line)
                value = get_all_key(line)
                size = get_value_size_key(line)
                
                if '.' in value:
                    value = struct.pack('>f', float(value))
                elif value.startswith('0x'):
                    value = int(value, 16).to_bytes(size, 'big', signed=False)
                else:
                    value = int(value).to_bytes(size, 'big', signed=False)

                prmfile.edit_value(key, value)
            
            for key in prmfile.sections.keys():
                params = prmfile.get_attributes(key)
                size = params[2]
                value = params[3]

                dump.write(bytes.fromhex(calc_key_code(key)) +
                           len(key).to_bytes(2, 'big', signed=False) +
                           key.encode('utf-8') +
                           size.to_bytes(4, 'big', signed=False) +
                           value)
                i += 1
        
        dump.seek(0)
        dump.write(i.to_bytes(4, 'big', signed=False))

def init_params(dump=None):
    if dump == None:
        dump = 'prm.txt'
    
    if not os.path.exists(os.path.dirname(dump)) and os.path.dirname(dump) not in ('', '/'):
        os.makedirs(os.path.dirname(dump))

    with open(dump, 'w+') as txtdump:
        txtdump.write(wrap_text('PRM', True) + '\n\n#Entries follow the format <key> <size>= <value>, key can be any non whitespace name you want.\n\n')
        txtdump.write('OurNewIntEntry'.ljust(24) + '<2>=\t' + '7;\n')
        txtdump.write('OurNewHexEntry'.ljust(24) + '<1>=\t' + '0xF0;\n')
        txtdump.write('OurNewFloatEntry'.ljust(24) + '<4>=\t' + '1.2345;\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='.prm parser for SMS modding',
                                     description='Create/Edit/Save/Extract .prm files',
                                     allow_abbrev=False)

    parser.add_argument('file', help='input file')
    parser.add_argument('-d', '--dump',
                        help='Dump parsed params.bin file output to a txt file',
                        action='store_true')
    parser.add_argument('-c', '--compile',
                        help='Compile a txt file into params.bin',
                        action='store_true')
    parser.add_argument('-i', '--init',
                        help='Create a clean txt template',
                        action='store_true')
    parser.add_argument('--dest',
                        help='Where to create/dump contents to',
                        metavar = 'filepath')
    parser.add_argument('--force',
                        help='''Forces the whole file to be updated,
                        rather than just the attributes''',
                        action='store_false')

    args = parser.parse_args()

    matchingfiles = glob.glob(args.file)

    if len(matchingfiles) > 1:
        considerfolder = True
    else:
        considerfolder = False

    try:
        if len(matchingfiles) > 0:
            for filename in matchingfiles:
                if not filename.lower().endswith('.prm') and args.dump == True:
                    print('Input file {} is not a .prm file'.format(filename))
                    continue
                elif not filename.lower().endswith('.txt') and args.compile == True:
                    print('Input file {} is not a .txt file'.format(filename))
                    continue
                
                if args.dump == True:
                    if args.dest is not None:
                        load_params(filename, args.dest, considerfolder)
                    else:
                        load_params(filename)
                elif args.compile == True:
                    if args.dest is not None:
                        save_params(filename, args.dest, obeyPrevAttrs=args.force, considerfolder=considerfolder)
                    else:
                        save_params(filename, obeyPrevAttrs=args.force)
                elif args.init == True:
                    init_params(filename)
                else:
                    parser.print_help(sys.stderr)
        else:
            if args.init == True:
                init_params(filename)
            else:
                parser.print_help(sys.stderr)
    except FileNotFoundError as e:
        parser.error(e)
        sys.exit(1)