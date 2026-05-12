import pathlib
import re


wrappers = {}


def gfunc_todo(func_name, reason=''):
    suffix = f': {reason}' if reason else ''
    wrappers[f'_GFUNC_:{func_name}'] = f'/* TODO:{func_name}{suffix} */'


def gfunc_not_support(func_name, reason=''):
    suffix = f': {reason}' if reason else ''
    wrappers[f'_GFUNC_:{func_name}'] = f'/* NotSupport:{func_name}{suffix} */'


def _load_from_template():
    template_path = pathlib.Path(__file__).with_name('func_wrappers.cpp')
    with open(template_path, encoding='utf-8') as file:
        text = file.read()
    for match in re.finditer(r'/\*START:(.*?)\*/(.*?)/\*END:\1\*/', text, re.DOTALL):
        wrappers[match.group(1)] = match.group(2).strip()


_load_from_template()


if __name__ == '__main__':
    for key, value in wrappers.items():
        print(f'{key}: {value}')
