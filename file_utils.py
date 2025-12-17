# file_utils.py
import json
from typing import Any, Dict

def write_json(filename: str, data: Dict[str, Any]):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def read_json(filename: str) -> Dict[str, Any]:
    with open(filename, "r") as f:
        return json.load(f)
