import re
import json
import sys
from pathlib import Path

# Add the project root (D:\WAScope) to Python's module search path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
import Config as Config
import lib
import lib.Utils as Utility
import Filter as Filter
from urllib.parse import parse_qsl


# json flatten handler
def flatten_json(json_data, prefix=''):
    flattened_data = {}
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            flattened_data.update(flatten_json(value, new_key))
    elif isinstance(json_data, list):
        for i, item in enumerate(json_data):
            new_key = f"{prefix}.{i}" if prefix else str(i)
            flattened_data.update(flatten_json(item, new_key))
    else:
        flattened_data = {prefix: json_data}
        # flattened_data = {"notJson": json_data}
    return flattened_data


# privacy data analysis for response
def content_analysis(_data):
    origin_params = None
    sensitive_params = None
    if Filter.check_is_json(_data):
        _dict = json.loads(_data)
        origin_params = flatten_json(_dict)
        # pattern = utils.pattern_handler(tpl_lib.params['sensitive'])
        pattern = Utility.pattern_handler(Config.privacy_tpl)
        sensitive_params = {}
        for key, value in origin_params.items():
            t = re.findall(pattern, key, re.IGNORECASE)
            if len(t) > 0:
                sensitive_params[t[0]] = value

    return origin_params, sensitive_params

def params_analysis(_data, _is_pay_load=False):
    # pattern = Utility.pattern_handler(Config.params['sensitive'])
    pattern = Utility.pattern_handler(Config.privacy_tpl)
    if _is_pay_load:
        params_list = Utility.pay_load_json_handler(_data)
        params_list.append(("pay_load_flag", ""))
    else:
        params = _data.split("?")[-1] if Filter.check_question_mark(_data) else _data
        # origin_params = dict(parse_qsl(params))
        params_list = parse_qsl(params)
    origin_params = {}
    for key, value in params_list:
        try:
            json_data = json.loads(value)
            origin_params[key] = json_data
        except json.JSONDecodeError:
            origin_params[key] = value

    sensitive_params = {}
    for key, value in origin_params.items():
        t = re.findall(pattern, key, re.IGNORECASE)
        if len(t) > 0:
            # sensitive_params.append({t[0]: value})
            sensitive_params[t[0]] = value
    # origin_params=checker.check_empty_collection(origin_params)
    # sensitive_params=checker.check_empty_collection(sensitive_params)
    return origin_params, sensitive_params

def path_analysis(_data):
    pattern = Utility.pattern_handler(Config.params['sensitive'])
    _path = _data.split("?")[0] if Filter.check_question_mark(_data) else _data
    path_params = _path.split("/")[1:]
    sensitive_params = []
    for path_item in path_params:
        t = re.findall(pattern, path_item, re.IGNORECASE)
        if len(t) > 0:
            sensitive_params.append(path_item)
    # path_params=checker.check_empty_collection(path_params)
    # sensitive_params=checker.check_empty_collection(sensitive_params)
    return path_params, sensitive_params
