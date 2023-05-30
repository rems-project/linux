#!/usr/bin/env python3

import argparse, os, json, re, sys

from pathlib import Path

def eprint(*args, then_exit=True, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    if then_exit:
        exit(1)

def extract_command(path):
    with open(path) as f:
        command = f.readline().strip('\n').split(':=')[1]
        if command.endswith('.c'):
            return command.strip()

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
    return 'cerberus -include cerb_work_around.h ' + ' '.join(x.group() for x in re.finditer('(-I|-include )\S+', cmd)) + ' ' + filename

def create_command(data, args):
    result = []
    for elem in data:
        if (filename := elem['file']).endswith(args.file_suffix):
            cmd = elem['command']
            if args.tool == "cerberus":
                cmd = cerberus(cmd, filename)
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
    
    if len(output) == 1:
        print(output[0])
        exit(0)
    elif len(output) == 0:
        eprint(f'*{args.file_suffix} not found in compile_commands.json')
    else:
        eprint(f'More than one file matching *{args.file_suffix} found in compile_commands.json', then_exit=False)
        eprint([ name for name in map(extract_filename, output) ])

parser = argparse.ArgumentParser(description="Helper script for generating commands.")
parser.set_defaults(func=(lambda _: parser.parse_args(['-h'])))

subparsers = parser.add_subparsers(title='subcommands', description='Choose which action to execute', help='Additional help')

parser_make = subparsers.add_parser('make',
        help='Generate a compile_commands.json file; run AFTER building pkvm.')

parser_make.set_defaults(func=write_compile_commands)

parser_for = subparsers.add_parser('for',
        help='Get the compile command for a file (and tool).')

parser_for.add_argument('--tool', choices=['pp', 'preprocess', 'cerberus'],
        required=False, help='Ouptut command for specifc use case.')

parser_for.add_argument('file_suffix',
        help='Uniquely identifying suffix of a file in compile_commands.json')

parser_for.set_defaults(func=for_file)

args = parser.parse_args()

# Call the func (as set using set_defaults for the parent & subcommands)
args.func(args)

