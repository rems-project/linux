#!/usr/bin/env python3

import argparse, os, json, re, sys

from pathlib import Path

def eprint(*args, then_exit=True, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    if then_exit:
        exit(1)

def extract_command(path):
    with open(path) as f:
        command = f.readline().strip('\n').split(':=')[1].strip()
        if command.endswith('.c'):
            return command

def extract_filename(cmd):
    return cmd.split()[-1]

def make_dict(cmd):
    return {
            "directory": os.getcwd(),
            "command": cmd,
            "file": extract_filename(cmd)
            }

def write_compile_commands(_):
    commands = (cmd for path in Path('.').rglob('*.cmd') if (cmd := extract_command(path)) is not None)
    dicts = [ make_dict(cmd) for cmd in commands ]
    if len(dicts) == 0:
        eprint('''\
No *.cmd for C files found. Have you built pkvm?
https://github.com/rems-project/pkvm-verif-private/blob/main/notes/notes019-2020-06-26-pkvm-build.md\
''')
    with open('compile_commands.json', 'w') as f:
        json.dump(dicts, f, indent=4)

def preprocess(cmd, filename):
    return re.sub(f'-c -o .* {filename}', f'--preprocess --comments --comments-in-macros {filename}', cmd)

def cerberus(cmd, filename):
    return re.sub(f'-include', f'--include',
            'cerberus -include cerb_work_around.h ' + ' '.join(x.group() for x in re.finditer(r'(-I|-include )\S+', cmd)) + ' ' + filename)

def cerberus_cn(cmd, filename):
    return re.sub(f'-include', f'--include',
            'cn -include cerb_work_around.h ' + ' '.join(x.group() for x in re.finditer(r'(-I|-include )\S+', cmd)) + ' ' + filename)

def create_command(data, args):
    result = []
    for elem in data:
        if (filename := elem['file']).endswith(args.file_suffix):
            cmd = elem['command'] if 'command' in elem else ' '.join(elem['arguments'])
            if args.tool == "cerberus":
                cmd = cerberus(cmd, filename)
            elif args.tool == "cn":
                cmd = cerberus_cn(cmd, filename)
            elif args.tool == "pp" or args.tool == "preprocess":
                cmd = preprocess(cmd, filename)
            result.append(cmd)
    return result

def for_file(args):
    try:
        with open('compile_commands.json') as f:
            data = json.load(f)
    except FileNotFoundError as e:
        eprint(f'File compile_commands.json not found. Try running `./compile_cmd.py make` first.')
    
    output = create_command(data, args)
    
    output_len = len(output)
    if output_len == 1:
        print(output[0])
        exit(0)
    elif output_len == 0:
        eprint(f'*{args.file_suffix} not found in compile_commands.json')
    elif args.n is not None:
        print(output[int(args.n)])
    else:
        eprint(f'More than one file matching *{args.file_suffix} found in compile_commands.json', then_exit=False)
        eprint([ name for name in map(extract_filename, output) ])

# top level
parser = argparse.ArgumentParser(description="Helper script for generating commands.")
parser.set_defaults(func=(lambda _: parser.parse_args(['-h'])))

# subparsers
subparsers = parser.add_subparsers(title='subcommands', description='Choose which action to execute', help='Additional help')

# make subcommand
parser_make = subparsers.add_parser('make',
        help='Generate a compile_commands.json file; run AFTER building pkvm.')
parser_make.set_defaults(func=write_compile_commands)

# for subcommand
parser_for = subparsers.add_parser('for',
        help='Get the compile command for a file (and tool).')
parser_for.add_argument('--tool', choices=['pp', 'preprocess', 'cerberus', 'cn'],
        help='Ouptut command for specifc use case.')
parser_for.add_argument('file_suffix',
        help='Suffix of a file in compile_commands.json')
parser_for.add_argument('-n',
        help='For multiple commands, choose one of them')
parser_for.set_defaults(func=for_file)

# Parse args and call func (as set using set_defaults)
args = parser.parse_args()
args.func(args)

