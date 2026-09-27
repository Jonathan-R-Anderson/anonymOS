import base64
import json
import time

import base58
import pytest
from nacl.signing import SigningKey
from starlette.requests import Request

from backend.schemas import RegistrationRequest
from backend.security import authenticate_request


class Session:
    def __init__(self):
        self.added = []

    async def execute(self, statement):
        return None

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        pass


def signed_request():
    key = SigningKey.generate()
    protobuf = b"\x08\x01\x12\x20" + bytes(key.verify_key)
    node_id = base58.b58encode(b"\x00\x24" + protobuf).decode()
    value = {
        "version": 1,
        "node_id": node_id,
        "public_key": base64.b64encode(protobuf).decode().rstrip("="),
        "public_hostname": "gw-one.syndichan.org",
        "port": 443,
        "timestamp": int(time.time()),
        "nonce": "a-unique-registration-nonce",
        "registration": {
            "node_id": node_id,
            "sequence": 1,
            "health_state": "healthy",
        },
    }
    raw = json.dumps(value, separators=(",", ":")).encode()
    signature = base64.b64encode(key.sign(raw).signature).decode().rstrip("=")
    headers = [
        (b"x-syndichan-node", node_id.encode()),
        (b"x-syndichan-signature", signature.encode()),
    ]
    request = Request(
        {"type": "http", "method": "POST", "path": "/", "headers": headers}
    )
    return raw, request, RegistrationRequest.model_validate(value)


@pytest.mark.asyncio
async def test_signed_registration_authenticates_without_shared_secret():
    raw, request, body = signed_request()
    session = Session()
    await authenticate_request(raw, request, body, session)
    assert len(session.added) == 1
    assert session.added[0].node_id == body.node_id


@pytest.mark.asyncio
async def test_registration_signature_binds_exact_body():
    raw, request, body = signed_request()
    with pytest.raises(Exception) as error:
        await authenticate_request(raw + b" ", request, body, Session())
    assert getattr(error.value, "status_code", None) == 401

