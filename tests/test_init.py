import json
from unittest.mock import MagicMock, patch

import pytest
from homeassistant.components.climate import \
    HVACMode  # Ensure HVACMode is imported
from homeassistant.core import HomeAssistant

from custom_components.gree.climate import \
    GCM_DEFAULT_KEY  # Import the correct default key used for binding
# Import MOCK constants from conftest using absolute path relative to tests dir
from tests.conftest import MOCK_IP, MOCK_MAC, MOCK_NAME, MOCK_PORT

# Fixtures (mock_hass, gree_climate_device) are automatically discovered from conftest.py

# --- Initialization Tests ---


async def test_init_minimal_config(gree_climate_device):
    """Test initialization with minimal configuration."""
    # Get the device instance by calling the factory
    device = gree_climate_device()
    # Basic checks after fixture instantiation
    assert device is not None
    assert device.name == MOCK_NAME
    assert device._ip_addr == MOCK_IP
    assert device._port == MOCK_PORT
    assert device._mac_addr == MOCK_MAC.replace(":", "").lower()
    assert device.hvac_mode == HVACMode.OFF  # Check default state
    # Check default encryption version
    assert device.encryption_version == 1
    assert device._encryption_key is None  # No key by default


async def test_init_with_encryption_key(gree_climate_device):
    """Test initialization with a configured encryption key (V1)."""
    mock_key = "testEncryptKey16"  # Ensure 16 bytes for AES-128
    # Get the device instance by calling the factory with args
    device = gree_climate_device(encryption_key=mock_key, encryption_version=1)

    assert device._encryption_key == mock_key.encode("utf8")
    assert device.encryption_version == 1
    # Check if the API object was initialized with the key
    assert device._api._encryption_key == mock_key.encode("utf8")
    assert device._api._encryption_version == 1
    assert device._api._cipher is not None  # API should create the cipher for V1
    assert (
        device.CIPHER is None
    )  # Should NOT be created directly in GreeClimate anymore


async def test_init_with_gcm_encryption(gree_climate_device):
    """Test initialization with GCM encryption (V2) and key."""
    mock_key = "testGcmKey123456"  # 16 bytes
    # Get the device instance by calling the factory with args
    device = gree_climate_device(encryption_key=mock_key, encryption_version=2)

    assert device._encryption_key == mock_key.encode("utf8")
    assert device.encryption_version == 2
    # Check if the API object was initialized correctly for V2
    assert device._api._encryption_key == mock_key.encode("utf8")
    assert device._api._encryption_version == 2
    assert device._api._cipher is None  # API should NOT create cipher on init for V2
    assert device.CIPHER is None


@pytest.mark.asyncio
@patch("custom_components.gree.device_api.GreeDeviceApi._fetch_result")
@patch("custom_components.gree.device_api.GreeDeviceApi._get_gcm_cipher")
@patch("custom_components.gree.device_api.GreeDeviceApi._encrypt_gcm")
async def test_get_device_key_gcm(
    mock_encrypt_gcm,
    mock_get_gcm_cipher,
    mock_fetch_result,
    gree_climate_device,
):
    """Test the GetDeviceKeyGCM method calls API correctly and returns key."""
    # INITIAL_GCM_KEY is not used by GetDeviceKeyGCM, binding uses default key
    NEW_GCM_KEY = "newBindingKey456"

    # Create a V2 device (initial key doesn't matter for this call)
    device_v2 = gree_climate_device(encryption_version=2)

    # Mock API call return values
    mock_pack = "mock_encrypted_bind_pack"
    mock_tag = "mock_bind_tag"
    mock_encrypt_gcm.return_value = (mock_pack, mock_tag)

    mock_gcm_cipher_instance = MagicMock()
    mock_get_gcm_cipher.return_value = mock_gcm_cipher_instance

    mock_fetch_result.return_value = {
        "key": NEW_GCM_KEY,
        "r": 200,
    }  # Simulate successful bind

    # Call the GCM binding method (synchronous)
    returned_key = device_v2.GetDeviceKeyGCM()

    # Assertions
    # 1. Check _encrypt_gcm call - Use the exact plaintext from GetDeviceKeyGCM
    # Replicate the f-string format used in bind_device_v2
    expected_bind_plaintext = (
        f'{{"cid":"{device_v2._mac_addr}","mac":"{device_v2._mac_addr}","t":"bind","uid":0}}'
    )

    # Use the correct bytes literal for the default key
    mock_encrypt_gcm.assert_called_once_with(
        b"{yxAHAY_Lm6pbC/<",  # Actual default key used in bind_device_v2
        expected_bind_plaintext,
    )

    # 2. Check _get_gcm_cipher call
    # This should also use the default key
    mock_get_gcm_cipher.assert_called_once_with(b"{yxAHAY_Lm6pbC/<")

    # 3. Check _fetch_result call (Payload has i=1 hardcoded in GetDeviceKeyGCM)
    expected_payload_dict = {
        "cid": "app",
        "i": 1,  # Actual code uses i=1 for binding
        "pack": mock_pack,
        "t": "pack",
        "tcid": device_v2._mac_addr,
        "uid": 0,
        "tag": mock_tag,
    }
    mock_fetch_result.assert_called_once()  # Check it was called
    actual_call_args, _ = mock_fetch_result.call_args
    actual_cipher_arg = actual_call_args[0]
    actual_payload_str = actual_call_args[1]

    assert actual_cipher_arg is mock_gcm_cipher_instance
    assert json.loads(actual_payload_str) == expected_payload_dict

    # 4. Check returned value and stored key
    assert returned_key is True
    # The key should now be stored within the API object
    assert device_v2._api._encryption_key == NEW_GCM_KEY.encode("utf8")


async def test_init_with_optional_entities(mock_hass: HomeAssistant):
    """Test initialization with optional entity IDs configured."""
    # Requires creating a device instance differently than the fixture
    # TODO: Implement this test, likely involves creating a GreeClimate instance
    #       directly here with specific entity IDs provided.
