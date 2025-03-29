import base64
import logging
import socket
from typing import Optional

from Crypto.Cipher import AES
from homeassistant.components.climate.const import HVACMode

try:
    import simplejson
except ImportError:
    import json as simplejson

_LOGGER = logging.getLogger(__name__)

# Placeholder constants for GCM (might need to be moved/configured)
GCM_IV = b"\0\0\0\0\0\0\0\0\0\0\0\0"
GCM_ADD = b""


class GreeDeviceApi:
    """Handles communication with a Gree device."""

    def __init__(
        self,
        host: str,
        port: int,
        mac: str,
        timeout: int,
        encryption_key: Optional[bytes] = None,
        encryption_version: int = 1,
    ):
        """Initialize the API."""
        _LOGGER.debug(
            "Initializing GreeDeviceApi for host %s (version %s)",
            host,
            encryption_version,
        )
        self._host = host
        self._port = port
        self._mac = mac
        self._timeout = timeout
        self._encryption_key = encryption_key
        self._encryption_version = encryption_version
        self._cipher = None

        if self._encryption_key and self._encryption_version == 1:
            self._cipher = AES.new(self._encryption_key, AES.MODE_ECB)
        elif not self._encryption_key:
            _LOGGER.debug("Encryption key not provided yet.")
        elif self._encryption_version != 1:
            _LOGGER.debug(
                "Encryption version %s uses different cipher setup.",
                self._encryption_version,
            )

    # Pad helper method to help us get the right string for encrypting
    def _pad(self, s: str) -> str:
        """Pads the string s to a multiple of the AES block size (16)."""
        aes_block_size = 16
        return s + (aes_block_size - len(s) % aes_block_size) * chr(
            aes_block_size - len(s) % aes_block_size
        )

    def _fetch_result(self, cipher, json_payload: str) -> dict:
        """Sends a JSON payload to the device and returns the decrypted response pack."""
        _LOGGER.debug(
            "Fetching from %s:%s with timeout %s",
            self._host,
            self._port,
            self._timeout,
        )
        # TODO: Handle socket errors, timeouts, JSON decoding errors, decryption errors gracefully
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.settimeout(self._timeout)
        try:
            client_sock.sendto(bytes(json_payload, "utf-8"), (self._host, self._port))
            data, _ = client_sock.recvfrom(64000)
        finally:
            client_sock.close()

        received_json = simplejson.loads(data)
        pack = received_json["pack"]
        base64decoded_pack = base64.b64decode(pack)

        # Decryption logic
        decrypted_pack = b""
        if self._encryption_version == 1:
            # Use the stored ECB cipher
            if not self._cipher:
                # This assumes the key/cipher was set via GetDeviceKey previously
                # TODO: Add more robust error handling if cipher is missing
                _LOGGER.error("ECB Cipher not initialized for V1 encryption!")
                # raise SomeAppropriateError("Cipher not ready")
                # For now, try creating it on the fly if key exists
                if self._encryption_key:
                    _LOGGER.warning("Attempting to create ECB cipher on the fly.")
                    self._cipher = AES.new(self._encryption_key, AES.MODE_ECB)
                else:
                    # Cannot proceed without key/cipher
                    raise ValueError("Cannot decrypt V1 data: key/cipher missing.")
            decrypted_pack = self._cipher.decrypt(base64decoded_pack)
        elif self._encryption_version == 2:
            if not self._encryption_key:
                raise ValueError("Cannot decrypt V2 data: key missing.")
            # Need the GCM cipher passed in - the one used for the *request* might not
            # be the right one if the key was just obtained *in* this response.
            # For now, assume the passed 'cipher' arg IS the correct GCM cipher for decrypt
            tag = received_json["tag"]
            try:
                decrypted_pack = cipher.decrypt_and_verify(
                    base64decoded_pack, base64.b64decode(tag)
                )
            except ValueError as e:
                _LOGGER.error("GCM decryption/verification failed: %s", e)
                raise  # Re-raise exception
        else:
            raise ValueError(
                f"Unsupported encryption version: {self._encryption_version}"
            )

        # Decode and remove padding/trailing characters
        decoded_pack = decrypted_pack.decode("utf-8")
        # This stripping logic might be fragile, needs review
        replaced_pack = decoded_pack.replace("\x0f", "").replace(
            decoded_pack[decoded_pack.rindex("}") + 1 :], ""
        )
        loaded_json_pack = simplejson.loads(replaced_pack)
        return loaded_json_pack

    def _get_gcm_cipher(self, key: bytes) -> AES.MODE_GCM:
        """Creates a GCM cipher instance with the specified key."""
        cipher = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
        cipher.update(GCM_ADD)
        return cipher

    def _encrypt_gcm(self, key: bytes, plaintext: str) -> tuple[str, str]:
        """Encrypts plaintext using GCM and returns base64 encoded pack and tag."""
        cipher = self._get_gcm_cipher(key)
        encrypted_data, tag = cipher.encrypt_and_digest(plaintext.encode("utf8"))
        pack = base64.b64encode(encrypted_data).decode("utf-8")
        tag = base64.b64encode(tag).decode("utf-8")
        return (pack, tag)

    # Add methods for binding, sending commands, receiving status, etc.
    def send_command(self, opt_keys: list[str], p_values: list) -> Optional[dict]:
        """Sends a command packet to the device."""
        _LOGGER.debug("Preparing to send command with opt=%s, p=%s", opt_keys, p_values)

        # Build the command payload dictionary
        if len(opt_keys) != len(p_values):
            _LOGGER.error(
                "send_command error: opt_keys length (%s) != p_values length (%s)",
                len(opt_keys),
                len(p_values)
            )
            return None # Or raise ValueError

        # Convert p_values - Note: Gree protocol might expect ints for bools, strings for enums etc.
        # This conversion might need refinement based on actual device behavior.
        converted_p_values = []
        for val in p_values:
            if isinstance(val, bool):
                converted_p_values.append(int(val))
            elif isinstance(val, HVACMode): # Handle HVACMode enum specifically
                converted_p_values.append(val.value) # Assuming .value gives the right representation
            elif val is None:
                # How should None be represented? Assuming 0 for now.
                _LOGGER.warning("Encountered None value in command params, representing as 0.")
                converted_p_values.append(0)
            elif isinstance(val, (str, int, float)):
                converted_p_values.append(val)
            else:
                 _LOGGER.error("Unsupported type in p_values for send_command: %s (%s)", val, type(val))
                 # Decide handling - maybe default to 0 or raise error?
                 converted_p_values.append(0) # Defaulting to 0 for now

        command_payload = {
            "opt": opt_keys,
            "p": converted_p_values,
            "t": "cmd"
        }

        # Construct the inner JSON command payload string using simplejson
        try:
            state_pack_json = simplejson.dumps(command_payload, separators=(",", ":"))
        except TypeError as e:
            _LOGGER.error("Error serializing command payload to JSON: %s", e)
            return None

        _LOGGER.debug("Constructed state_pack_json: %s", state_pack_json)

        sent_json_payload = None
        cipher_for_fetch = None # Cipher needed for _fetch_result (mainly for v2 decryption)

        if self._encryption_version == 1:
            if not self._cipher:
                _LOGGER.error("Cannot send V1 command: ECB cipher not initialized.")
                # Potentially try to bind/get key first? Or just fail.
                return None # Or raise exception
            cipher_for_fetch = self._cipher # Use the instance's ECB cipher

            padded_state = self._pad(state_pack_json).encode("utf8")
            encrypted_pack = base64.b64encode(cipher_for_fetch.encrypt(padded_state)).decode("utf-8")

            sent_json_payload = (
                f'{{\"cid\":\"app\",\"i\":0,\"pack\":\"{encrypted_pack}\",'
                f'\"t\":\"pack\",\"tcid\":\"{self._mac}\",'
                f'\"uid\":0}}' # Assuming uid 0 for commands, confirm if needed
            )

        elif self._encryption_version == 2:
            if not self._encryption_key:
                _LOGGER.error("Cannot send V2 command: Encryption key missing.")
                # Potentially try to bind/get key first? Or just fail.
                return None # Or raise exception

            # Encrypt using the instance's key
            pack, tag = self._encrypt_gcm(self._encryption_key, state_pack_json)

            # Get the GCM cipher instance required for decrypting the response in _fetch_result
            cipher_for_fetch = self._get_gcm_cipher(self._encryption_key)

            sent_json_payload = (
                f'{{\"cid\":\"app\",\"i\":0,\"pack\":\"{pack}\",'
                f'\"t\":\"pack\",\"tcid\":\"{self._mac}\",'
                f'\"uid\":0,\"tag\":\"{tag}\"}}' # Assuming uid 0 for commands, confirm if needed
            )
        else:
            _LOGGER.error(
                "Unsupported encryption version: %s. Cannot send command.",
                self._encryption_version,
            )
            return None # Or raise an exception

        if sent_json_payload is None or cipher_for_fetch is None:
             _LOGGER.error("Failed to prepare command payload or cipher.")
             return None # Should have been caught earlier, but safety check

        try:
            # Call the internal fetch method
            _LOGGER.debug("Sending payload: %s", sent_json_payload)
            received_json_pack = self._fetch_result(cipher_for_fetch, sent_json_payload)
            _LOGGER.debug("Received response pack: %s", received_json_pack)
            return received_json_pack
        except (socket.timeout, socket.error) as e:
            _LOGGER.error("Socket error sending command: %s", e)
            return None
        except (simplejson.JSONDecodeError, ValueError) as e:
             _LOGGER.error("Error processing response after sending command: %s", e)
             return None
        except Exception as e: # Catch any other unexpected errors
             _LOGGER.error("Unexpected error sending command: %s", e, exc_info=True)
             return None

    def get_status(self, property_names: list[str]) -> Optional[dict]:
        """Fetches the status of specified properties from the device."""
        _LOGGER.debug("Preparing to get status for properties: %s", property_names)

        # Construct the inner JSON status request payload
        try:
            cols_json = simplejson.dumps(property_names)
        except TypeError as e:
            _LOGGER.error("Error serializing property names to JSON: %s", e)
            return None

        plaintext_payload = (
            f'{{\"cols\":{cols_json},\"mac\":\"{self._mac}\",\"t\":\"status\"}}'
        )

        sent_json_payload = None
        cipher_for_fetch = None # Cipher needed for _fetch_result (mainly for v2 decryption)

        if self._encryption_version == 1:
            if not self._cipher:
                _LOGGER.error("Cannot get V1 status: ECB cipher not initialized.")
                return None # Or raise exception
            cipher_for_fetch = self._cipher

            padded_state = self._pad(plaintext_payload).encode("utf8")
            encrypted_pack = base64.b64encode(cipher_for_fetch.encrypt(padded_state)).decode("utf-8")

            sent_json_payload = (
                f'{{\"cid\":\"app\",\"i\":0,\"pack\":\"{encrypted_pack}\",'
                f'\"t\":\"pack\",\"tcid\":\"{self._mac}\",'
                f'\"uid\":0}}' # Assuming uid 0 for status, confirm if needed
            )

        elif self._encryption_version == 2:
            if not self._encryption_key:
                _LOGGER.error("Cannot get V2 status: Encryption key missing.")
                return None # Or raise exception

            # Encrypt using the instance's key
            pack, tag = self._encrypt_gcm(self._encryption_key, plaintext_payload)

            # Get the GCM cipher instance required for decrypting the response
            cipher_for_fetch = self._get_gcm_cipher(self._encryption_key)

            sent_json_payload = (
                f'{{\"cid\":\"app\",\"i\":0,\"pack\":\"{pack}\",'
                f'\"t\":\"pack\",\"tcid\":\"{self._mac}\",'
                f'\"uid\":0,\"tag\":\"{tag}\"}}' # Assuming uid 0 for status, confirm if needed
            )
        else:
            _LOGGER.error(
                "Unsupported encryption version: %s. Cannot get status.",
                self._encryption_version,
            )
            return None # Or raise an exception

        if sent_json_payload is None or cipher_for_fetch is None:
             _LOGGER.error("Failed to prepare status request payload or cipher.")
             return None # Should have been caught earlier, but safety check

        try:
            # Call the internal fetch method
            _LOGGER.debug("Sending status request payload: %s", sent_json_payload)
            received_json_pack = self._fetch_result(cipher_for_fetch, sent_json_payload)
            _LOGGER.debug("Received status response pack: %s", received_json_pack)

            # Extract the 'dat' field which contains the status values
            if "dat" in received_json_pack:
                return received_json_pack["dat"]
            else:
                _LOGGER.error("'dat' field missing from status response: %s", received_json_pack)
                return None
        except (socket.timeout, socket.error) as e:
            _LOGGER.error("Socket error getting status: %s", e)
            return None
        except (simplejson.JSONDecodeError, ValueError) as e:
             _LOGGER.error("Error processing response after getting status: %s", e)
             return None
        except Exception as e: # Catch any other unexpected errors
             _LOGGER.error("Unexpected error getting status: %s", e, exc_info=True)
             return None

    def bind_device_v1(self) -> bool:
        """Binds the device using V1 (ECB) encryption to get the real encryption key."""
        _LOGGER.info("Attempting to bind device (V1) to retrieve encryption key...")
        GENERIC_GREE_DEVICE_KEY = b"a3K8Bx%2r8Y7#xDh" # Note: use bytes

        try:
            # Create a temporary cipher with the generic key
            generic_cipher = AES.new(GENERIC_GREE_DEVICE_KEY, AES.MODE_ECB)

            # Create the binding payload
            bind_payload = f'{{\"mac\":\"{self._mac}\",\"t\":\"bind\",\"uid\":0}}'

            # Pad and encrypt the payload
            padded_data = self._pad(bind_payload).encode("utf8")
            encrypted_pack = base64.b64encode(generic_cipher.encrypt(padded_data)).decode("utf-8")

            # Create the full JSON packet to send
            json_payload_to_send = (
                f'{{\"cid\":\"app\",\"i\":1,\"pack\":\"{encrypted_pack}\",'
                f'\"t\":\"pack\",\"tcid\":\"{self._mac}\",\"uid\":0}}'
            )

            _LOGGER.debug("Sending V1 bind request payload: %s", json_payload_to_send)
            # Call fetch_result using the temporary generic cipher
            result = self._fetch_result(generic_cipher, json_payload_to_send)

            if "key" in result:
                self._encryption_key = result["key"].encode("utf8")
                self._cipher = AES.new(self._encryption_key, AES.MODE_ECB)
                _LOGGER.info("Successfully bound device (V1) and received key: %s", self._encryption_key)
                return True
            else:
                _LOGGER.error("Binding V1 failed: 'key' not found in response: %s", result)
                return False

        except (socket.timeout, socket.error) as e:
            _LOGGER.error("Socket error during V1 binding: %s", e)
            return False
        except (simplejson.JSONDecodeError, ValueError, KeyError) as e:
             _LOGGER.error("Error processing response during V1 binding: %s", e)
             return False
        except Exception as e: # Catch any other unexpected errors
             _LOGGER.error("Unexpected error during V1 binding: %s", e, exc_info=True)
             return False

    def bind_device_v2(self) -> bool:
        """Binds the device using V2 (GCM) encryption to get the real encryption key."""
        _LOGGER.info("Attempting to bind device (V2) to retrieve encryption key...")
        GENERIC_GREE_GCM_KEY = b"{yxAHAY_Lm6pbC/<" # Use bytes

        try:
            # Create the plaintext binding payload
            # Note: cid is the mac address for V2 binding?
            plaintext_payload = (
                 f'{{\"cid\":\"{self._mac}\",\"mac\":\"{self._mac}\",\"t\":\"bind\",\"uid\":0}}'
            )

            # Encrypt using the generic GCM key
            pack, tag = self._encrypt_gcm(GENERIC_GREE_GCM_KEY, plaintext_payload)

            # Create the full JSON packet to send
            json_payload_to_send = (
                f'{{\"cid\":\"app\",\"i\":1,\"pack\":\"{pack}\",'
                f'\"t\":\"pack\",\"tcid\":\"{self._mac}\",\"uid\":0,\"tag\":\"{tag}\"}}'
            )

            _LOGGER.debug("Sending V2 bind request payload: %s", json_payload_to_send)

            # Get the GCM cipher instance associated with the *generic* key for decryption
            generic_gcm_cipher = self._get_gcm_cipher(GENERIC_GREE_GCM_KEY)

            # Call fetch_result using the generic GCM cipher
            result = self._fetch_result(generic_gcm_cipher, json_payload_to_send)

            if "key" in result:
                self._encryption_key = result["key"].encode("utf8")
                # For V2, we don't store a persistent cipher, we create it as needed using the key
                _LOGGER.info("Successfully bound device (V2) and received key: %s", self._encryption_key)
                return True
            else:
                _LOGGER.error("Binding V2 failed: 'key' not found in response: %s", result)
                return False

        except (socket.timeout, socket.error) as e:
            _LOGGER.error("Socket error during V2 binding: %s", e)
            return False
        except (simplejson.JSONDecodeError, ValueError, KeyError) as e:
             _LOGGER.error("Error processing response during V2 binding: %s", e)
             return False
        except Exception as e: # Catch any other unexpected errors
             _LOGGER.error("Unexpected error during V2 binding: %s", e, exc_info=True)
             return False
