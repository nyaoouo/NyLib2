import json
import re
import yaml # PyYAML
import time
import logging

MODE_DICT = 1
MODE_LIST = 2
DICT_MODE_KEY = 1
DICT_MODE_VALUE = -1

regex_num = re.compile(r'[+-]?\d+(\.\d+)?')
control_escape = re.compile(r'[\x00-\x08\x0B\x0C\x0E\x0F\x7F\x80-\x84\x86\x9F\uD800-\uDFFF\uFFFE\uFFFF]')


def fmt_progress(progress: int):
    assert 0 <= progress <= 100, Exception("progress not in range")
    _s = int(progress % 5)
    raw = "█" * (progress // 5)
    if _s: raw += " ▎▍▋▊"[_s]
    return f"[{raw + ' ' * (20 - len(raw))}]"


def parse_value(value: str):
    # if value == 'True': return "true"
    # if value == 'False': return "false"
    if regex_num.match(value): return value
    return json.dumps(value)


def parse(yaml_path, json_path, indent=2, log=False):
    logger = logging.getLogger('Yaml2Json') if log else None
    with open(yaml_path, 'r', encoding='utf-8') as yaml_file, open(json_path, 'w', encoding='utf-8') as json_file:
        yaml_file.seek(0, 2)
        total_size = yaml_file.tell()
        yaml_file.seek(0)
        mode_stack = []
        prefix = ''
        counter = []
        current_mode = 0
        current_counter = 0
        _prefix = ['\n' + ' ' * indent * i for i in range(100)]

        def push_mode(mode):
            nonlocal current_mode, current_counter, prefix
            mode_stack.append(current_mode)
            counter.append(current_counter)
            current_mode = mode
            current_counter = 0
            prefix = _prefix[len(mode_stack)]

        def pop_mode():
            nonlocal current_mode, current_counter, prefix
            current_mode = mode_stack.pop()
            current_counter = counter.pop()
            prefix = _prefix[len(mode_stack)]
            current_counter += 1

        def on_mapping_start_event(evt):
            if current_mode == MODE_LIST:
                if current_counter: json_file.write(',')
                json_file.write(prefix)
            json_file.write('{')
            push_mode(MODE_DICT)

        def on_mapping_end_event(evt):
            pop_mode()
            json_file.write(prefix + '}')

        def on_sequence_start_event(evt):
            if current_mode == MODE_LIST:
                if current_counter: json_file.write(',')
                json_file.write(prefix)
            json_file.write('[')
            push_mode(MODE_LIST)

        def on_sequence_end_event(evt):
            pop_mode()
            json_file.write(prefix + ']')

        def on_scalar_event(evt):
            nonlocal current_counter
            if current_mode == MODE_LIST:
                if current_counter: json_file.write(',')
                json_file.write(prefix + parse_value(evt.value))
            else:
                if current_counter % 2:  # is_value
                    json_file.write(parse_value(evt.value))
                else:  # is_key
                    if current_counter: json_file.write(',')
                    json_file.write(prefix + json.dumps(evt.value) + ' :')
            current_counter += 1

        def default_evt(evt):
            print(f'unknown event:{evt}')

        event_map = {
            yaml.ScalarEvent: on_scalar_event,
            yaml.MappingStartEvent: on_mapping_start_event,
            yaml.MappingEndEvent: on_mapping_end_event,
            yaml.SequenceStartEvent: on_sequence_start_event,
            yaml.SequenceEndEvent: on_sequence_end_event,
            yaml.DocumentStartEvent: lambda _: None,
            yaml.DocumentEndEvent: lambda _: None,
            yaml.StreamStartEvent: lambda _: None,
            yaml.StreamEndEvent: lambda _: None,
        }
        old_read = yaml_file.read
        yaml_file.read = lambda n=-1: control_escape.sub('', old_read(n))
        parser = yaml.parse(yaml_file, Loader=yaml.CSafeLoader)
        start = time.time()
        next_update = start + 1
        if logger:
            logger.debug(f'[00%]parsing {yaml_path}:{fmt_progress(0)}(0/-1s)')
        for event in parser:
            current = time.time()
            if current >= next_update:
                next_update = current + 1
                percent = yaml_file.tell() * 100 / total_size
                over_time = current - start
                if logger: logger.debug(f'[{percent:02.0f}%]parsing {yaml_path}:{fmt_progress(int(percent))}({over_time:.0f}/{over_time / percent * 100:.0f}s)')
            event_map.get(type(event), default_evt)(event)
        if logger: logger.debug(f'[100%]parsed {yaml_path}:{fmt_progress(100)}({time.time() - start:.0f}s)')
