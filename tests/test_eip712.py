import pytest

from approvalaudit.eip712 import TypedDataError, digest, domain_separator, encode_type, hash_struct

# The worked example from EIP-712 (eips.ethereum.org/EIPS/eip-712, Example.js).
MAIL = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}


def test_eip712_reference_vectors() -> None:
    assert encode_type("Mail", MAIL["types"]) == (  # type: ignore[arg-type]
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    )
    assert domain_separator(MAIL).hex() == "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    assert (
        hash_struct("Mail", MAIL["message"], MAIL["types"]).hex()  # type: ignore[arg-type]
        == "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    )
    assert digest(MAIL).hex() == "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"


def test_changing_any_field_changes_the_digest() -> None:
    import copy

    base = digest(MAIL)
    for path in (("domain", "chainId"), ("message", "contents")):
        doc = copy.deepcopy(MAIL)
        doc[path[0]][path[1]] = 5 if path[1] == "chainId" else "Hello, Eve!"  # type: ignore[index]
        assert digest(doc) != base


@pytest.mark.parametrize(
    ("t", "v"),
    [("uint8", 256), ("uint256", -1), ("int8", 128), ("bytes4", "0x0102"), ("bool", 1), ("address", "0x12")],
)
def test_values_must_fit(t: str, v: object) -> None:
    from approvalaudit.eip712 import encode_value

    with pytest.raises(TypedDataError):
        encode_value(t, v, {})


def test_arrays_and_numbers_as_strings() -> None:
    from approvalaudit.eip712 import encode_value

    assert encode_value("uint256", "0x10", {}) == encode_value("uint256", 16, {})
    assert encode_value("uint256", "16", {}) == encode_value("uint256", 16, {})
    assert encode_value("int8", -1, {}) == b"\xff" * 32
    with pytest.raises(TypedDataError):
        encode_value("uint8[2]", [1], {})
