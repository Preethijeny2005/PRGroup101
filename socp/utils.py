# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import json
import uuid
import datetime
import base64
from typing import Any, Dict

def json_canonicalize(obj: Any) -> str:
    """
    Deterministic JSON canonicalization:
    - sort keys
    - no extra whitespace (separators(',',':'))
    - UTF-8 encoding is used when converting to bytes for signing
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def now_ts_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def make_envelope(type_: str, from_id: str, to_id: str | None, payload: Dict) -> Dict:
    env = {
        "id": str(uuid.uuid4()),
        "type": type_,
        "from": from_id,
        "ts": now_ts_iso(),
        "payload": payload
    }
    if to_id is not None:
        env["to"] = to_id
    return env

def b64url_encode_no_padding(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64url_decode_no_padding(s: str) -> bytes:
    padding = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)
