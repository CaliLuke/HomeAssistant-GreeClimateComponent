#!/usr/bin/python
# Do basic imports
import base64
import logging
from datetime import timedelta

# Use simplejson if available, otherwise fall back to standard json
try:
    import simplejson as json
except ImportError:
    import json

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from Crypto.Cipher import AES
from homeassistant.components.climate import (PLATFORM_SCHEMA, ClimateEntity,
                                              ClimateEntityFeature, HVACMode)
from homeassistant.const import (ATTR_TEMPERATURE, ATTR_UNIT_OF_MEASUREMENT,
                                 CONF_HOST, CONF_MAC, CONF_NAME, CONF_PORT,
                                 CONF_TIMEOUT, STATE_OFF, STATE_ON,
                                 STATE_UNKNOWN)
from homeassistant.core import Event, callback
from homeassistant.helpers.event import (EventStateChangedData,
                                         async_track_state_change_event)

# Import the new API class
from .device_api import GreeDeviceApi

REQUIREMENTS = ["pycryptodome"]

_LOGGER = logging.getLogger(__name__)

SUPPORT_FLAGS = (
    ClimateEntityFeature.TARGET_TEMPERATURE
    | ClimateEntityFeature.FAN_MODE
    | ClimateEntityFeature.SWING_MODE
    | ClimateEntityFeature.TURN_ON
    | ClimateEntityFeature.TURN_OFF
)

DEFAULT_NAME = "Gree Climate"

CONF_TARGET_TEMP_STEP = "target_temp_step"
CONF_TEMP_SENSOR = "temp_sensor"
CONF_LIGHTS = "lights"
CONF_XFAN = "xfan"
CONF_HEALTH = "health"
CONF_POWERSAVE = "powersave"
CONF_SLEEP = "sleep"
CONF_EIGHTDEGHEAT = "eightdegheat"
CONF_AIR = "air"
CONF_ENCRYPTION_KEY = "encryption_key"
CONF_UID = "uid"
CONF_AUTO_XFAN = "auto_xfan"
CONF_AUTO_LIGHT = "auto_light"
CONF_TARGET_TEMP = "target_temp"
CONF_HORIZONTAL_SWING = "horizontal_swing"
CONF_ANTI_DIRECT_BLOW = "anti_direct_blow"
CONF_ENCRYPTION_VERSION = "encryption_version"
CONF_DISABLE_AVAILABLE_CHECK = "disable_available_check"
CONF_MAX_ONLINE_ATTEMPTS = "max_online_attempts"
CONF_LIGHT_SENSOR = "light_sensor"

DEFAULT_PORT = 7000
DEFAULT_TIMEOUT = 10
DEFAULT_TARGET_TEMP_STEP = 1

# from the remote control and gree app
MIN_TEMP = 16
MAX_TEMP = 30

# update() interval
SCAN_INTERVAL = timedelta(seconds=60)

TEMP_OFFSET = 40

# fixed values in gree mode lists
HVAC_MODES = [
    HVACMode.AUTO,
    HVACMode.COOL,
    HVACMode.DRY,
    HVACMode.FAN_ONLY,
    HVACMode.HEAT,
    HVACMode.OFF,
]

FAN_MODES = [
    "Auto",
    "Low",
    "Medium-Low",
    "Medium",
    "Medium-High",
    "High",
    "Turbo",
    "Quiet",
]
SWING_MODES = [
    "Default",
    "Swing in full range",
    "Fixed in the upmost position",
    "Fixed in the middle-up position",
    "Fixed in the middle position",
    "Fixed in the middle-low position",
    "Fixed in the lowest position",
    "Swing in the downmost region",
    "Swing in the middle-low region",
    "Swing in the middle region",
    "Swing in the middle-up region",
    "Swing in the upmost region",
]
PRESET_MODES = [
    "Default",
    "Full swing",
    "Fixed in the leftmost position",
    "Fixed in the middle-left position",
    "Fixed in the middle postion",
    "Fixed in the middle-right position",
    "Fixed in the rightmost position",
]

# GCM Constants (Placeholder - Values depend on actual Gree protocol reverse engineering)
GCM_DEFAULT_KEY = "{yxAHAY_Lm6pbC/<"  # Default key for GCM binding based on logs
GCM_IV = b"\x00" * 12  # Initialization Vector (often 12 bytes for GCM)
GCM_ADD = b""  # Additional Authenticated Data (if used by protocol)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): cv.positive_int,
        vol.Required(CONF_MAC): cv.string,
        vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
        vol.Optional(
            CONF_TARGET_TEMP_STEP, default=DEFAULT_TARGET_TEMP_STEP
        ): vol.Coerce(float),
        vol.Optional(CONF_TEMP_SENSOR): cv.entity_id,
        vol.Optional(CONF_LIGHTS): cv.entity_id,
        vol.Optional(CONF_XFAN): cv.entity_id,
        vol.Optional(CONF_HEALTH): cv.entity_id,
        vol.Optional(CONF_POWERSAVE): cv.entity_id,
        vol.Optional(CONF_SLEEP): cv.entity_id,
        vol.Optional(CONF_EIGHTDEGHEAT): cv.entity_id,
        vol.Optional(CONF_AIR): cv.entity_id,
        vol.Optional(CONF_ENCRYPTION_KEY): cv.string,
        vol.Optional(CONF_UID): cv.positive_int,
        vol.Optional(CONF_AUTO_XFAN): cv.entity_id,
        vol.Optional(CONF_AUTO_LIGHT): cv.entity_id,
        vol.Optional(CONF_TARGET_TEMP): cv.entity_id,
        vol.Optional(CONF_ENCRYPTION_VERSION, default=1): cv.positive_int,
        vol.Optional(CONF_HORIZONTAL_SWING, default=False): cv.boolean,
        vol.Optional(CONF_ANTI_DIRECT_BLOW): cv.entity_id,
        vol.Optional(CONF_DISABLE_AVAILABLE_CHECK, default=False): cv.boolean,
        vol.Optional(CONF_MAX_ONLINE_ATTEMPTS, default=3): cv.positive_int,
        vol.Optional(CONF_LIGHT_SENSOR): cv.entity_id,
    }
)


async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    _LOGGER.info("Setting up Gree climate platform")
    name = config.get(CONF_NAME)
    ip_addr = config.get(CONF_HOST)
    port = config.get(CONF_PORT)
    mac_addr = config.get(CONF_MAC).encode().replace(b":", b"")
    timeout = config.get(CONF_TIMEOUT)

    target_temp_step = config.get(CONF_TARGET_TEMP_STEP)
    temp_sensor_entity_id = config.get(CONF_TEMP_SENSOR)
    lights_entity_id = config.get(CONF_LIGHTS)
    xfan_entity_id = config.get(CONF_XFAN)
    health_entity_id = config.get(CONF_HEALTH)
    powersave_entity_id = config.get(CONF_POWERSAVE)
    sleep_entity_id = config.get(CONF_SLEEP)
    eightdegheat_entity_id = config.get(CONF_EIGHTDEGHEAT)
    air_entity_id = config.get(CONF_AIR)
    target_temp_entity_id = config.get(CONF_TARGET_TEMP)
    hvac_modes = HVAC_MODES
    fan_modes = FAN_MODES
    swing_modes = SWING_MODES
    preset_modes = PRESET_MODES
    encryption_key = config.get(CONF_ENCRYPTION_KEY)
    uid = config.get(CONF_UID)
    auto_xfan_entity_id = config.get(CONF_AUTO_XFAN)
    auto_light_entity_id = config.get(CONF_AUTO_LIGHT)
    horizontal_swing = config.get(CONF_HORIZONTAL_SWING)
    anti_direct_blow_entity_id = config.get(CONF_ANTI_DIRECT_BLOW)
    light_sensor_entity_id = config.get(CONF_LIGHT_SENSOR)
    encryption_version = config.get(CONF_ENCRYPTION_VERSION)
    disable_available_check = config.get(CONF_DISABLE_AVAILABLE_CHECK)
    max_online_attempts = config.get(CONF_MAX_ONLINE_ATTEMPTS)

    _LOGGER.info("Adding Gree climate device to hass")

    async_add_devices(
        [
            GreeClimate(
                hass,
                name,
                ip_addr,
                port,
                mac_addr,
                timeout,
                target_temp_step,
                temp_sensor_entity_id,
                lights_entity_id,
                xfan_entity_id,
                health_entity_id,
                powersave_entity_id,
                sleep_entity_id,
                eightdegheat_entity_id,
                air_entity_id,
                target_temp_entity_id,
                anti_direct_blow_entity_id,
                hvac_modes,
                fan_modes,
                swing_modes,
                preset_modes,
                auto_xfan_entity_id,
                auto_light_entity_id,
                horizontal_swing,
                light_sensor_entity_id,
                encryption_version,
                disable_available_check,
                max_online_attempts,
                encryption_key,
                uid,
            )
        ]
    )


class GreeClimate(ClimateEntity):

    def __init__(
        self,
        hass,
        name,
        ip_addr,
        port,
        mac_addr,
        timeout,
        target_temp_step,
        temp_sensor_entity_id,
        lights_entity_id,
        xfan_entity_id,
        health_entity_id,
        powersave_entity_id,
        sleep_entity_id,
        eightdegheat_entity_id,
        air_entity_id,
        target_temp_entity_id,
        anti_direct_blow_entity_id,
        hvac_modes,
        fan_modes,
        swing_modes,
        preset_modes,
        auto_xfan_entity_id,
        auto_light_entity_id,
        horizontal_swing,
        light_sensor_entity_id,
        encryption_version,
        disable_available_check,
        max_online_attempts,
        encryption_key=None,
        uid=None,
    ):
        _LOGGER.info("Initialize the GREE climate device")
        self.hass = hass
        self._name = name
        self._ip_addr = ip_addr
        self._port = port
        self._mac_addr = mac_addr.decode("utf-8").lower()
        self._timeout = timeout
        self._unique_id = "climate.gree_" + mac_addr.decode("utf-8").lower()
        self._device_online = None
        self._online_attempts = 0
        self._max_online_attempts = max_online_attempts
        self._disable_available_check = disable_available_check

        self._target_temperature = None
        self._target_temperature_step = target_temp_step
        self._unit_of_measurement = "°C"

        self._hvac_modes = hvac_modes
        self._hvac_mode = HVACMode.OFF
        self._fan_modes = fan_modes
        self._fan_mode = None
        self._swing_modes = swing_modes
        self._swing_mode = None
        self._preset_modes = preset_modes
        self._preset_mode = None

        self._temp_sensor_entity_id = temp_sensor_entity_id
        self._lights_entity_id = lights_entity_id
        self._xfan_entity_id = xfan_entity_id
        self._health_entity_id = health_entity_id
        self._powersave_entity_id = powersave_entity_id
        self._sleep_entity_id = sleep_entity_id
        self._eightdegheat_entity_id = eightdegheat_entity_id
        self._air_entity_id = air_entity_id
        self._target_temp_entity_id = target_temp_entity_id
        self._anti_direct_blow_entity_id = anti_direct_blow_entity_id
        self._light_sensor_entity_id = light_sensor_entity_id
        self._auto_xfan_entity_id = auto_xfan_entity_id
        self._auto_light_entity_id = auto_light_entity_id

        self._horizontal_swing = horizontal_swing
        self._has_temp_sensor = None
        self._has_anti_direct_blow = None
        self._has_light_sensor = None

        self._current_temperature = None
        self._current_lights = None
        self._current_xfan = None
        self._current_health = None
        self._current_powersave = None
        self._current_sleep = None
        self._current_eightdegheat = None
        self._current_air = None
        self._current_anti_direct_blow = None

        self._firstTimeRun = True

        self._enable_turn_on_off_backwards_compatibility = False

        self.encryption_version = encryption_version
        self.CIPHER = None

        # Instantiate the API handler
        self._api = GreeDeviceApi(
            host=ip_addr,
            port=port,
            mac=mac_addr.decode("utf-8").lower(),  # Pass decoded MAC
            timeout=timeout,
            encryption_key=(
                encryption_key.encode("utf8") if encryption_key else None
            ),  # Pass key if exists
            encryption_version=encryption_version,  # Pass version
        )

        if encryption_key:
            _LOGGER.info("Using configured encryption key: {}".format(encryption_key))
            self._encryption_key = encryption_key.encode("utf8")
            # Store reference to key in GreeClimate for now, might be removable later
            if encryption_version == 1:
                # CIPHER object is now managed by GreeDeviceApi for v1
                # We might still need a reference here or ways to get it from the API
                # For now, let's remove direct CIPHER creation here to avoid duplication
                # self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
                pass  # Handled by API init
            elif encryption_version != 2:
                _LOGGER.error(
                    "Encryption version %s is not implemented." % self._encryption_version
                )
        else:
            self._encryption_key = None

        if uid:
            self._uid = uid
        else:
            self._uid = 0

        self._acOptions = {
            "Pow": None,
            "Mod": None,
            "SetTem": None,
            "WdSpd": None,
            "Air": None,
            "Blo": None,
            "Health": None,
            "SwhSlp": None,
            "Lig": None,
            "SwingLfRig": None,
            "SwUpDn": None,
            "Quiet": None,
            "Tur": None,
            "StHt": None,
            "TemUn": None,
            "HeatCoolType": None,
            "TemRec": None,
            "SvSt": None,
            "SlpMod": None,
        }
        self._optionsToFetch = [
            "Pow",
            "Mod",
            "SetTem",
            "WdSpd",
            "Air",
            "Blo",
            "Health",
            "SwhSlp",
            "Lig",
            "SwingLfRig",
            "SwUpDn",
            "Quiet",
            "Tur",
            "StHt",
            "TemUn",
            "HeatCoolType",
            "TemRec",
            "SvSt",
            "SlpMod",
        ]

        if temp_sensor_entity_id:
            _LOGGER.info("Setting up temperature sensor: " + str(temp_sensor_entity_id))
            async_track_state_change_event(
                hass, temp_sensor_entity_id, self._async_temp_sensor_changed
            )

        if lights_entity_id:
            _LOGGER.info("Setting up lights entity: " + str(lights_entity_id))
            async_track_state_change_event(
                hass, lights_entity_id, self._async_lights_entity_state_changed
            )

        if xfan_entity_id:
            _LOGGER.info("Setting up xfan entity: " + str(xfan_entity_id))
            async_track_state_change_event(
                hass, xfan_entity_id, self._async_xfan_entity_state_changed
            )

        if health_entity_id:
            _LOGGER.info("Setting up health entity: " + str(health_entity_id))
            async_track_state_change_event(
                hass, health_entity_id, self._async_health_entity_state_changed
            )

        if powersave_entity_id:
            _LOGGER.info("Setting up powersave entity: " + str(powersave_entity_id))
            async_track_state_change_event(
                hass, powersave_entity_id, self._async_powersave_entity_state_changed
            )

        if sleep_entity_id:
            _LOGGER.info("Setting up sleep entity: " + str(sleep_entity_id))
            async_track_state_change_event(
                hass, sleep_entity_id, self._async_sleep_entity_state_changed
            )

        if eightdegheat_entity_id:
            _LOGGER.info("Setting up 8℃ heat entity: " + str(eightdegheat_entity_id))
            async_track_state_change_event(
                hass,
                eightdegheat_entity_id,
                self._async_eightdegheat_entity_state_changed,
            )

        if air_entity_id:
            _LOGGER.info("Setting up air entity: " + str(air_entity_id))
            async_track_state_change_event(
                hass, air_entity_id, self._async_air_entity_state_changed
            )

        if target_temp_entity_id:
            _LOGGER.info("Setting up target temp entity: " + str(target_temp_entity_id))
            async_track_state_change_event(
                hass,
                target_temp_entity_id,
                self._async_target_temp_entity_state_changed,
            )

        if anti_direct_blow_entity_id:
            _LOGGER.info(
                "Setting up anti direct blow entity: " + str(anti_direct_blow_entity_id)
            )
            async_track_state_change_event(
                hass,
                anti_direct_blow_entity_id,
                self._async_anti_direct_blow_entity_state_changed,
            )

        if light_sensor_entity_id:
            _LOGGER.info(
                "Setting up light sensor entity: " + str(light_sensor_entity_id)
            )
            if (
                self.hass.states.get(light_sensor_entity_id) is not None
                and self.hass.states.get(light_sensor_entity_id).state is STATE_ON
            ):
                self._enable_light_sensor = True
            else:
                self._enable_light_sensor = False
            async_track_state_change_event(
                hass,
                light_sensor_entity_id,
                self._async_light_sensor_entity_state_changed,
            )
        else:
            self._enable_light_sensor = False

        if auto_light_entity_id:
            _LOGGER.info("Setting up auto light entity: " + str(auto_light_entity_id))
            if (
                self.hass.states.get(auto_light_entity_id) is not None
                and self.hass.states.get(auto_light_entity_id).state is STATE_ON
            ):
                self._auto_light = True
            else:
                self._auto_light = False
            async_track_state_change_event(
                hass, auto_light_entity_id, self._async_auto_light_entity_state_changed
            )
        else:
            self._auto_light = False

        if auto_xfan_entity_id:
            _LOGGER.info("Setting up auto xfan entity: " + str(auto_xfan_entity_id))
            if (
                self.hass.states.get(auto_xfan_entity_id) is not None
                and self.hass.states.get(auto_xfan_entity_id).state is STATE_ON
            ):
                self._auto_xfan = True
            else:
                self._auto_xfan = False
            async_track_state_change_event(
                hass, auto_xfan_entity_id, self._async_auto_xfan_entity_state_changed
            )
        else:
            self._auto_xfan = False

    def GetDeviceKey(self):
        _LOGGER.info("Attempting to bind device and retrieve encryption key via API (V1)...")
        try:
            # Delegate binding to the API method
            success = self._api.bind_device_v1()

            if success:
                _LOGGER.info("Successfully retrieved encryption key via API (V1).")
                # Update HA state
                self._device_online = True
                self._online_attempts = 0
                return True
            else:
                _LOGGER.error("API failed to bind device or retrieve key (V1).")
                self._device_online = False
                self._online_attempts = 0
                # Should we reset self._api._encryption_key or self._api._cipher here? Probably not needed.
                return False

        except Exception as e:
            # Catch potential exceptions from the API call itself (though handled internally)
            _LOGGER.error("Unexpected error calling self._api.bind_device_v1: %s", e, exc_info=True)
            self._device_online = False
            self._online_attempts = 0
            return False

    def GetDeviceKeyGCM(self):
        _LOGGER.info("Attempting to bind device and retrieve encryption key via API (V2/GCM)...")
        try:
            # Delegate binding to the API method
            success = self._api.bind_device_v2()

            if success:
                _LOGGER.info("Successfully retrieved encryption key via API (V2/GCM).")
                # Update HA state
                self._device_online = True
                self._online_attempts = 0
                # Note: _encryption_key is now stored within self._api for V2
                return True
            else:
                _LOGGER.error("API failed to bind device or retrieve key (V2/GCM).")
                self._device_online = False
                self._online_attempts = 0
                return False

        except Exception as e:
            # Catch potential exceptions from the API call itself (though handled internally)
            _LOGGER.error("Unexpected error calling self._api.bind_device_v2: %s", e, exc_info=True)
            self._device_online = False
            self._online_attempts = 0
            return False

    def GreeGetValues(self, propertyNames):
        _LOGGER.debug("Calling API get_status for properties: %s", propertyNames)
        try:
            # Delegate fetching status to the API method
            status_data = self._api.get_status(propertyNames)

            if status_data is not None:
                _LOGGER.debug("Successfully received status data via API: %s", status_data)
                return status_data
            else:
                _LOGGER.error("API get_status returned None, indicating failure.")
                # Return empty dict to match original behavior on error
                return {}
        except Exception as e:
            _LOGGER.error("Error calling self._api.get_status: %s", e, exc_info=True)
            # Return empty dict to match original behavior on error
            return {}

    def SetAcOptions(
        self, acOptions, newOptionsToOverride, optionValuesToOverride=None
    ):
        if optionValuesToOverride is not None:
            _LOGGER.info("Setting acOptions with retrieved HVAC values")
            for key in newOptionsToOverride:
                _LOGGER.info(
                    "Setting %s: %s"
                    % (key, optionValuesToOverride[newOptionsToOverride.index(key)])
                )
                acOptions[key] = optionValuesToOverride[newOptionsToOverride.index(key)]
            _LOGGER.info("Done setting acOptions")
        else:
            _LOGGER.info("Overwriting acOptions with new settings")
            for key, value in newOptionsToOverride.items():
                _LOGGER.info("Overwriting %s: %s" % (key, value))
                acOptions[key] = value
            _LOGGER.info("Done overwriting acOptions")
        return acOptions

    def SendStateToAc(self, timeout):
        # Define default options
        opt_keys = [
            "Pow", "Mod", "SetTem", "WdSpd", "Air", "Blo", "Health", "SwhSlp",
            "Lig", "SwingLfRig", "SwUpDn", "Quiet", "Tur", "StHt", "TemUn",
            "HeatCoolType", "TemRec", "SvSt", "SlpMod"
        ]

        # Add optional features if enabled
        if self._has_anti_direct_blow:
            opt_keys.append("AntiDirectBlow")
        if self._has_light_sensor:
            opt_keys.append("LigSen")

        # Get the corresponding values from _acOptions
        # Note: Ensure the order matches opt_keys precisely!
        p_values = [self._acOptions.get(key) for key in opt_keys]

        _LOGGER.debug(
            "Calling API send_command with opt_keys: %s, p_values: %s",
            opt_keys,
            p_values,
        )

        # Call the API method to handle sending the command
        # Pass opt_keys and the corresponding values
        # The API method now handles JSON construction, encryption, and network I/O
        try:
            receivedJsonPayload = self._api.send_command(opt_keys, p_values)

            if receivedJsonPayload:
                _LOGGER.info("Successfully sent command via API. Response pack: %s", receivedJsonPayload)
                # Potentially process the response here if needed by GreeClimate
                # For now, just logging success.
                return receivedJsonPayload # Return the response pack
            else:
                _LOGGER.error("API send_command returned None or False, indicating failure.")
                return None
        except Exception as e:
            _LOGGER.error("Error calling self._api.send_command: %s", e, exc_info=True)
            return None

    def UpdateHATargetTemperature(self):
        # Sync set temperature to HA. If 8℃ heating is active we set the temp in HA to 8℃ so that it shows the same as the AC display.
        if int(self._acOptions["StHt"]) == 1:
            self._target_temperature = 8
            _LOGGER.info(
                "HA target temp set according to HVAC state to 8℃ since 8℃ heating mode is active"
            )
        else:
            self._target_temperature = self._acOptions["SetTem"]
            if self._target_temp_entity_id:
                target_temp_state = self.hass.states.get(self._target_temp_entity_id)
                if target_temp_state:
                    attr = target_temp_state.attributes
                    if self._target_temperature in range(MIN_TEMP, MAX_TEMP + 1):
                        self.hass.states.async_set(
                            self._target_temp_entity_id,
                            float(self._target_temperature),
                            attr,
                        )
            _LOGGER.info(
                "HA target temp set according to HVAC state to: %s",
                self._acOptions["SetTem"],
            )

    def UpdateHAOptions(self):
        # Sync HA with retreived HVAC options
        # WdSpd = fanspeed (0=auto), SvSt = powersave, Air = Air in/out (1=air in, 2=air out), Health = health
        # SwhSlp,SlpMod = sleep (both needed for sleep deactivation), StHt = 8℃ deg heating, Lig = lights, Blo = xfan
        # Sync current HVAC lights option to HA
        if self._acOptions["Lig"] == 1:
            self._current_lights = STATE_ON
        elif self._acOptions["Lig"] == 0:
            self._current_lights = STATE_OFF
        else:
            self._current_lights = STATE_UNKNOWN
        if self._lights_entity_id:
            lights_state = self.hass.states.get(self._lights_entity_id)
            if lights_state:
                attr = lights_state.attributes
                if self._current_lights in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._lights_entity_id,
                        self._current_lights,
                        attr,
                    )
        _LOGGER.info(
            "HA lights option set according to HVAC state to: %s",
            self._current_lights,
        )
        # Sync current HVAC xfan option to HA
        if self._acOptions["Blo"] == 1:
            self._current_xfan = STATE_ON
        elif self._acOptions["Blo"] == 0:
            self._current_xfan = STATE_OFF
        else:
            self._current_xfan = STATE_UNKNOWN
        if self._xfan_entity_id:
            xfan_state = self.hass.states.get(self._xfan_entity_id)
            if xfan_state:
                attr = xfan_state.attributes
                if self._current_xfan in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._xfan_entity_id, self._current_xfan, attr
                    )
        _LOGGER.info(
            "HA xfan option set according to HVAC state to: %s",
            self._current_xfan,
        )
        # Sync current HVAC health option to HA
        if self._acOptions["Health"] == 1:
            self._current_health = STATE_ON
        elif self._acOptions["Health"] == 0:
            self._current_health = STATE_OFF
        else:
            self._current_health = STATE_UNKNOWN
        if self._health_entity_id:
            health_state = self.hass.states.get(self._health_entity_id)
            if health_state:
                attr = health_state.attributes
                if self._current_health in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._health_entity_id, self._current_health, attr
                    )
        _LOGGER.info(
            "HA health option set according to HVAC state to: %s",
            self._current_health,
        )
        # Sync current HVAC powersave option to HA
        if self._acOptions["SvSt"] == 1:
            self._current_powersave = STATE_ON
        elif self._acOptions["SvSt"] == 0:
            self._current_powersave = STATE_OFF
        else:
            self._current_powersave = STATE_UNKNOWN
        if self._powersave_entity_id:
            powersave_state = self.hass.states.get(self._powersave_entity_id)
            if powersave_state:
                attr = powersave_state.attributes
                if self._current_powersave in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._powersave_entity_id, self._current_powersave, attr
                    )
        _LOGGER.info(
            "HA powersave option set according to HVAC state to: %s",
            self._current_powersave,
        )
        # Sync current HVAC sleep option to HA
        if (self._acOptions["SwhSlp"] == 1) and (self._acOptions["SlpMod"] == 1):
            self._current_sleep = STATE_ON
        elif (self._acOptions["SwhSlp"] == 0) and (self._acOptions["SlpMod"] == 0):
            self._current_sleep = STATE_OFF
        else:
            self._current_sleep = STATE_UNKNOWN
        if self._sleep_entity_id:
            sleep_state = self.hass.states.get(self._sleep_entity_id)
            if sleep_state:
                attr = sleep_state.attributes
                if self._current_sleep in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._sleep_entity_id, self._current_sleep, attr
                    )
        _LOGGER.info(
            "HA sleep option set according to HVAC state to: %s",
            self._current_sleep,
        )
        # Sync current HVAC 8℃ heat option to HA
        if self._acOptions["StHt"] == 1:
            self._current_eightdegheat = STATE_ON
        elif self._acOptions["StHt"] == 0:
            self._current_eightdegheat = STATE_OFF
        else:
            self._current_eightdegheat = STATE_UNKNOWN
        if self._eightdegheat_entity_id:
            eightdegheat_state = self.hass.states.get(self._eightdegheat_entity_id)
            if eightdegheat_state:
                attr = eightdegheat_state.attributes
                if self._current_eightdegheat in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._eightdegheat_entity_id, self._current_eightdegheat, attr
                    )
        _LOGGER.info(
            "HA 8℃ heat option set according to HVAC state to: %s",
            self._current_eightdegheat,
        )
        # Sync current HVAC air option to HA
        if self._acOptions["Air"] == 1:
            self._current_air = STATE_ON
        elif self._acOptions["Air"] == 0:
            self._current_air = STATE_OFF
        else:
            self._current_air = STATE_UNKNOWN
        if self._air_entity_id:
            air_state = self.hass.states.get(self._air_entity_id)
            if air_state:
                attr = air_state.attributes
                if self._current_air in (STATE_ON, STATE_OFF):
                    self.hass.states.async_set(
                        self._air_entity_id, self._current_air, attr
                    )
        _LOGGER.info(
            "HA air option set according to HVAC state to: %s",
            self._current_air,
        )
        # Sync current HVAC anti direct blow option to HA
        if self._has_anti_direct_blow:
            if self._acOptions["AntiDirectBlow"] == 1:
                self._current_anti_direct_blow = STATE_ON
            elif self._acOptions["AntiDirectBlow"] == 0:
                self._current_anti_direct_blow = STATE_OFF
            else:
                self._current_anti_direct_blow = STATE_UNKNOWN
            if self._anti_direct_blow_entity_id:
                adb_state = self.hass.states.get(self._anti_direct_blow_entity_id)
                if adb_state:
                    attr = adb_state.attributes
                    if self._current_anti_direct_blow in (STATE_ON, STATE_OFF):
                        self.hass.states.async_set(
                            self._anti_direct_blow_entity_id,
                            self._current_anti_direct_blow,
                            attr,
                        )
            _LOGGER.info(
                "HA anti direct blow option set according to HVAC state to: %s",
                self._current_anti_direct_blow,
            )

    def UpdateHAHvacMode(self):
        # Sync current HVAC operation mode to HA
        if self._acOptions["Pow"] == 0:
            self._hvac_mode = HVACMode.OFF
        else:
            self._hvac_mode = self._hvac_modes[self._acOptions["Mod"]]
        _LOGGER.info(
            "HA operation mode set according to HVAC state to: %s",
            self._hvac_mode,
        )

    def UpdateHACurrentSwingMode(self):
        # Sync current HVAC Swing mode state to HA
        self._swing_mode = self._swing_modes[self._acOptions["SwUpDn"]]
        _LOGGER.info(
            "HA swing mode set according to HVAC state to: %s",
            self._swing_mode,
        )

    def UpdateHACurrentPresetMode(self):
        # Sync current HVAC preset mode state to HA
        self._preset_mode = self._preset_modes[self._acOptions["SwingLfRig"]]
        _LOGGER.info(
            "HA preset mode set according to HVAC state to: %s",
            self._preset_mode,
        )

    def UpdateHAFanMode(self):
        # Sync current HVAC Fan mode state to HA
        if int(self._acOptions["Tur"]) == 1:
            self._fan_mode = "Turbo"
        elif int(self._acOptions["Quiet"]) >= 1:
            self._fan_mode = "Quiet"
        else:
            self._fan_mode = self._fan_modes[int(self._acOptions["WdSpd"])]
        _LOGGER.info(
            "HA fan mode set according to HVAC state to: %s",
            self._fan_mode,
        )

    def UpdateHACurrentTemperature(self):
        if not self._temp_sensor_entity_id:
            if self._has_temp_sensor:
                temp = (
                    self._acOptions["TemSen"]
                    if self._acOptions["TemSen"] <= TEMP_OFFSET
                    else self._acOptions["TemSen"] - TEMP_OFFSET
                )
                self._current_temperature = self.hass.config.units.temperature(
                    float(temp), self._unit_of_measurement
                )
                _LOGGER.info(
                    "HA current temperature set with device built-in temperature sensor state : "
                    + str(self._current_temperature)
                )

    def UpdateHAStateToCurrentACState(self):
        self.UpdateHATargetTemperature()
        self.UpdateHAOptions()
        self.UpdateHAHvacMode()
        self.UpdateHACurrentSwingMode()
        if self._horizontal_swing:
            self.UpdateHACurrentPresetMode()
        self.UpdateHAFanMode()
        self.UpdateHACurrentTemperature()

    def SyncState(self, acOptions={}):
        # Fetch current settings from HVAC
        _LOGGER.info("Starting SyncState")

        if not self._temp_sensor_entity_id:
            if self._has_temp_sensor is None:
                _LOGGER.info(
                    "Attempt to check whether device has an built-in temperature sensor"
                )
                try:
                    temp_sensor = self.GreeGetValues(["TemSen"])
                except:
                    _LOGGER.info(
                        "Could not determine whether device has an built-in temperature sensor. Retrying at next update()"
                    )
                else:
                    if temp_sensor:
                        self._has_temp_sensor = True
                        self._acOptions.update({"TemSen": None})
                        self._optionsToFetch.append("TemSen")
                        _LOGGER.info("Device has an built-in temperature sensor")
                    else:
                        self._has_temp_sensor = False
                        _LOGGER.info("Device has no built-in temperature sensor")

        if self._anti_direct_blow_entity_id:
            if self._has_anti_direct_blow is None:
                _LOGGER.info(
                    "Attempt to check whether device has an anti direct blow feature"
                )
                try:
                    anti_direct_blow = self.GreeGetValues(["AntiDirectBlow"])
                except:
                    _LOGGER.info(
                        "Could not determine whether device has an anti direct blow feature. Retrying at next update()"
                    )
                else:
                    if anti_direct_blow:
                        self._has_anti_direct_blow = True
                        self._acOptions.update({"AntiDirectBlow": None})
                        self._optionsToFetch.append("AntiDirectBlow")
                        _LOGGER.info("Device has an anti direct blow feature")
                    else:
                        self._has_anti_direct_blow = False
                        _LOGGER.info("Device has no anti direct blow feature")

        if self._light_sensor_entity_id:
            if self._has_light_sensor is None:
                _LOGGER.info(
                    "Attempt to check whether device has an built-in light sensor"
                )
                try:
                    light_sensor = self.GreeGetValues(["LigSen"])
                except:
                    _LOGGER.info(
                        "Could not determine whether device has an built-in light sensor. Retrying at next update()"
                    )
                else:
                    if light_sensor:
                        self._has_light_sensor = True
                        self._acOptions.update({"LigSen": None})
                        self._optionsToFetch.append("LigSen")
                        _LOGGER.info("Device has an built-in light sensor")
                    else:
                        self._has_light_sensor = False
                        _LOGGER.info("Device has no built-in light sensor")

        optionsToFetch = self._optionsToFetch

        try:
            currentValues = self.GreeGetValues(optionsToFetch)
        except:
            _LOGGER.info("Could not connect with device. ")
            if not self._disable_available_check:
                self._online_attempts += 1
                if self._online_attempts == self._max_online_attempts:
                    _LOGGER.info(
                        "Could not connect with device %s times. Set it as offline.",
                         self._max_online_attempts
                    )
                    self._device_online = False
                    self._online_attempts = 0
        else:
            if not self._disable_available_check:
                if not self._device_online:
                    self._device_online = True
                    self._online_attempts = 0
            # Set latest status from device
            self._acOptions = self.SetAcOptions(
                self._acOptions, optionsToFetch, currentValues
            )

            # Overwrite status with our choices
            if acOptions != {}:
                self._acOptions = self.SetAcOptions(self._acOptions, acOptions)

            # Initialize the receivedJsonPayload variable (for return)
            receivedJsonPayload = ""

            # If not the first (boot) run, update state towards the HVAC
            if not self._firstTimeRun:
                if acOptions != {}:
                    # loop used to send changed settings from HA to HVAC
                    self.SendStateToAc(self._timeout)
            else:
                # loop used once for Gree Climate initialisation only
                self._firstTimeRun = False

            # Update HA state to current HVAC state
            self.UpdateHAStateToCurrentACState()

            _LOGGER.info("Finished SyncState")
            return receivedJsonPayload

    async def _async_temp_sensor_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            "temp_sensor state changed | %s from %s to %s",
            entity_id,
            old_state_str,
            new_state.state,
        )
        # Handle temperature changes.
        if new_state is None:
            return
        self._async_update_current_temp(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_temp(self, state):
        _LOGGER.info(
            "Thermostat updated with changed temp_sensor state | " + str(state.state)
        )
        unit = state.attributes.get(ATTR_UNIT_OF_MEASUREMENT)
        try:
            _state = state.state
            _LOGGER.info("Current state temp_sensor: " + _state)
            if self.represents_float(_state):
                self._current_temperature = self.hass.config.units.temperature(
                    float(_state), unit
                )
                _LOGGER.info("Current temp: " + str(self._current_temperature))
        except ValueError as ex:
            _LOGGER.error("Unable to update from temp_sensor: %s" % ex)

    def represents_float(self, s):
        _LOGGER.info("temp_sensor state represents_float |" + str(s))
        try:
            float(s)
            return True
        except ValueError:
            return False

    async def _async_lights_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"lights_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "lights_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_lights:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_current_lights(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_lights(self, state):
        _LOGGER.info(
            "Updating HVAC with changed lights_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"Lig": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"Lig": 0})
            return
        _LOGGER.error("Unable to update from lights_entity!")

    async def _async_xfan_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"xfan_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "xfan_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_xfan:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        if self._hvac_mode not in (HVACMode.COOL, HVACMode.DRY):
            # do nothing if not in cool or dry mode
            _LOGGER.info("Cant set xfan in %s mode" % str(self._hvac_mode))
            return
        self._async_update_current_xfan(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_xfan(self, state):
        _LOGGER.info(
            "Updating HVAC with changed xfan_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"Blo": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"Blo": 0})
            return
        _LOGGER.error("Unable to update from xfan_entity!")

    async def _async_health_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"health_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "health_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_health:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_current_health(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_health(self, state):
        _LOGGER.info(
            "Updating HVAC with changed health_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"Health": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"Health": 0})
            return
        _LOGGER.error("Unable to update from health_entity!")

    async def _async_powersave_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        _LOGGER.info(
            f"powersave_entity state changed: {entity_id} "
            f"from {old_state.state} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "powersave_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_powersave:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        if not hasattr(self, "_hvac_mode"):
            _LOGGER.info("Cant set powersave in unknown mode")
            return
        if self._hvac_mode is None:
            _LOGGER.info(
                "Cant set powersave in unknown HVAC mode (self._hvac_mode is None)"
            )
            return
        if self._hvac_mode not in (HVACMode.COOL):
            # do nothing if not in cool mode
            _LOGGER.info("Cant set powersave in %s mode" % str(self._hvac_mode))
            return
        self._async_update_current_powersave(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_powersave(self, state):
        _LOGGER.info(
            "Udating HVAC with changed powersave_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"SvSt": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"SvSt": 0})
            return
        _LOGGER.error("Unable to update from powersave_entity!")

    async def _async_sleep_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"sleep_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "sleep_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_sleep:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        if self._hvac_mode not in (HVACMode.COOL, HVACMode.HEAT):
            # do nothing if not in cool or heat mode
            _LOGGER.info("Cant set sleep in %s mode" % str(self._hvac_mode))
            return
        self._async_update_current_sleep(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_sleep(self, state):
        _LOGGER.info(
            "Updating HVAC with changed sleep_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"SwhSlp": 1, "SlpMod": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"SwhSlp": 0, "SlpMod": 0})
            return
        _LOGGER.error("Unable to update from sleep_entity!")

    async def _async_eightdegheat_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"eightdegheat_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "eightdegheat_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_eightdegheat:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        if self._hvac_mode not in (HVACMode.HEAT):
            # do nothing if not in heat mode
            _LOGGER.info("Cant set 8℃ heat in %s mode" % str(self._hvac_mode))
            return
        self._async_update_current_eightdegheat(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_eightdegheat(self, state):
        _LOGGER.info(
            "Updating HVAC with changed eightdegheat_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"StHt": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"StHt": 0})
            return
        _LOGGER.error("Unable to update from eightdegheat_entity!")

    def _async_air_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"air_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "air_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._current_air:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_current_air(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_air(self, state):
        _LOGGER.info(
            "Updating HVAC with changed air_entity state | " + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"Air": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"Air": 0})
            return
        _LOGGER.error("Unable to update from air_entity!")

    def _async_anti_direct_blow_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        if self._has_anti_direct_blow:
            entity_id = event.data["entity_id"]
            old_state = event.data["old_state"]
            new_state = event.data["new_state"]
            _LOGGER.info(
                f"anti_direct_blow_entity state changed: {entity_id} "
                f"from {old_state.state} to {new_state.state}"
            )
            if new_state is None:
                return
            if new_state.state == "off" and (
                old_state is None or old_state.state is None
            ):
                _LOGGER.info(
                    "anti_direct_blow_entity state changed to off, but old state is None. Ignoring to avoid beeps."
                )
                return
            if new_state.state is self._current_anti_direct_blow:
                # do nothing if state change is triggered due to Sync with HVAC
                return
            self._async_update_current_anti_direct_blow(new_state)
            return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_anti_direct_blow(self, state):
        _LOGGER.info(
            "Updating HVAC with changed anti_direct_blow_entity state | "
            + str(state.state)
        )
        if state.state is STATE_ON:
            self.SyncState({"AntiDirectBlow": 1})
            return
        elif state.state is STATE_OFF:
            self.SyncState({"AntiDirectBlow": 0})
            return
        _LOGGER.error("Unable to update from anti_direct_blow_entity!")

    def _async_light_sensor_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"light_sensor_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "light_sensor_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if new_state.state is self._enable_light_sensor:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_light_sensor(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_light_sensor(self, state):
        _LOGGER.info(
            "Updating enable_light_sensor with changed light_sensor_entity state | "
            + str(state.state)
        )
        if state.state is STATE_ON:
            self._enable_light_sensor = True
            if self._has_light_sensor and self._hvac_mode != HVACMode.OFF:
                self.SyncState({"Lig": 1, "LigSen": 0})
            return
        elif state.state is STATE_OFF:
            self._enable_light_sensor = False
            return
        _LOGGER.error("Unable to update from light_sensor_entity!")

    def _async_auto_light_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"auto_light_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "auto_light_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if not hasattr(self, "_auto_light"):
            _LOGGER.info(
                "auto_light_entity state changed | auto_light not (yet) initialized. Skipping."
            )
            return
        if new_state.state is self._auto_light:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_auto_light(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_auto_light(self, state):
        _LOGGER.info(
            "Updating auto_light with changed auto_light_entity state | "
            + str(state.state)
        )
        if state.state is STATE_ON:
            self._auto_light = True
            if self._hvac_mode != HVACMode.OFF:
                self.SyncState({"Lig": 1})
            else:
                self.SyncState({"Lig": 0})
            return
        elif state.state is STATE_OFF:
            self._auto_light = False
            return
        _LOGGER.error("Unable to update from auto_light_entity!")

    def _async_auto_xfan_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"auto_xfan_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "auto_xfan_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if not hasattr(self, "_auto_xfan"):
            _LOGGER.info(
                "auto_xfan_entity state changed | auto_xfan not (yet) initialized. Skipping."
            )
            return
        if new_state.state is self._auto_xfan:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_auto_xfan(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_auto_xfan(self, state):
        _LOGGER.info(
            "Updating auto_xfan with changed auto_xfan_entity state | "
            + str(state.state)
        )
        if state.state is STATE_ON:
            self._auto_xfan = True
            return
        elif state.state is STATE_OFF:
            self._auto_xfan = False
            self.SyncState({"Blo": 0})
            return
        _LOGGER.error("Unable to update from auto_xfan_entity!")

    def _async_target_temp_entity_state_changed(
        self, event: Event[EventStateChangedData]
    ) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        old_state_str = str(old_state.state) if hasattr(old_state, "state") else "None"
        _LOGGER.info(
            f"target_temp_entity state changed: {entity_id} "
            f"from {old_state_str} to {new_state.state}"
        )
        if new_state is None:
            return
        if new_state.state == "off" and (old_state is None or old_state.state is None):
            _LOGGER.info(
                "target_temp_entity state changed to off, but old state is None. Ignoring to avoid beeps."
            )
            return
        if int(float(new_state.state)) is self._target_temperature:
            # do nothing if state change is triggered due to Sync with HVAC
            return
        self._async_update_current_target_temp(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_target_temp(self, state):
        s = int(float(state.state))
        _LOGGER.info("Updating HVAC with changed target_temp_entity state | " + str(s))
        if (s >= MIN_TEMP) and (s <= MAX_TEMP):
            self.SyncState({"SetTem": s})
            return
        _LOGGER.error("Unable to update from target_temp_entity!")

    @property
    def should_poll(self):
        _LOGGER.info("should_poll()")
        # Return the polling state.
        return True

    @property
    def available(self):
        if self._disable_available_check:
            return True
        else:
            if self._device_online:
                _LOGGER.info("available(): Device is online")
                return True
            else:
                _LOGGER.info("available(): Device is offline")
                return False

    def update(self):
        _LOGGER.info("update()")
        if not self._encryption_key:
            if self.encryption_version == 1:
                if self.GetDeviceKey():
                    self.SyncState()
            elif self.encryption_version == 2:
                if self.GetDeviceKeyGCM():
                    self.SyncState()
            else:
                _LOGGER.error(
                    "Encryption version %s is not implemented." % self._encryption_version
                )
        else:
            self.SyncState()

    @property
    def name(self):
        _LOGGER.info("name(): " + str(self._name))
        # Return the name of the climate device.
        return self._name

    @property
    def temperature_unit(self):
        _LOGGER.info("temperature_unit(): " + str(self._unit_of_measurement))
        # Return the unit of measurement.
        return self._unit_of_measurement

    @property
    def current_temperature(self):
        _LOGGER.info("current_temperature(): " + str(self._current_temperature))
        # Return the current temperature.
        return self._current_temperature

    @property
    def min_temp(self):
        _LOGGER.info("min_temp(): " + str(MIN_TEMP))
        # Return the minimum temperature.
        return MIN_TEMP

    @property
    def max_temp(self):
        _LOGGER.info("max_temp(): " + str(MAX_TEMP))
        # Return the maximum temperature.
        return MAX_TEMP

    @property
    def target_temperature(self):
        _LOGGER.info("target_temperature(): " + str(self._target_temperature))
        # Return the temperature we try to reach.
        return self._target_temperature

    @property
    def target_temperature_step(self):
        _LOGGER.info("target_temperature_step(): " + str(self._target_temperature_step))
        # Return the supported step of target temperature.
        return self._target_temperature_step

    @property
    def hvac_mode(self):
        _LOGGER.info("hvac_mode(): " + str(self._hvac_mode))
        # Return current operation mode ie. heat, cool, idle.
        return self._hvac_mode

    @property
    def swing_mode(self):
        _LOGGER.info("swing_mode(): " + str(self._swing_mode))
        # get the current swing mode
        return self._swing_mode

    @property
    def swing_modes(self):
        _LOGGER.info("swing_modes(): " + str(self._swing_modes))
        # get the list of available swing modes
        return self._swing_modes

    @property
    def preset_mode(self):
        if hasattr(self, "_horizontal_swing") and self._horizontal_swing:
            _LOGGER.info("preset_mode(): " + str(self._preset_mode))
            # get the current preset mode
            return self._preset_mode
        else:
            return None

    @property
    def preset_modes(self):
        _LOGGER.info("preset_modes(): " + str(self._preset_modes))
        # get the list of available preset modes
        return self._preset_modes

    @property
    def hvac_modes(self):
        _LOGGER.info("hvac_modes(): " + str(self._hvac_modes))
        # Return the list of available operation modes.
        return self._hvac_modes

    @property
    def fan_mode(self):
        _LOGGER.info("fan_mode(): " + str(self._fan_mode))
        # Return the fan mode.
        return self._fan_mode

    @property
    def fan_modes(self):
        _LOGGER.info("fan_list(): " + str(self._fan_modes))
        # Return the list of available fan modes.
        return self._fan_modes

    @property
    def supported_features(self):
        if hasattr(self, "_horizontal_swing") and self._horizontal_swing:
            sf = SUPPORT_FLAGS | ClimateEntityFeature.PRESET_MODE
        else:
            sf = SUPPORT_FLAGS
        _LOGGER.info("supported_features(): " + str(sf))
        # Return the list of supported features.
        return sf

    @property
    def unique_id(self):
        # Return unique_id
        return self._unique_id

    def set_temperature(self, **kwargs):
        _LOGGER.info("set_temperature(): " + str(kwargs.get(ATTR_TEMPERATURE)))
        # Set new target temperatures.
        if kwargs.get(ATTR_TEMPERATURE) is not None:
            # do nothing if temperature is none
            if self._acOptions["Pow"] != 0:
                # do nothing if HVAC is switched off
                _LOGGER.info(
                    "SyncState with SetTem=" + str(kwargs.get(ATTR_TEMPERATURE))
                )
                self.SyncState({"SetTem": int(kwargs.get(ATTR_TEMPERATURE))})
                self.schedule_update_ha_state()

    def set_swing_mode(self, swing_mode):
        _LOGGER.info("Set swing mode(): " + str(swing_mode))
        # set the swing mode
        if self._acOptions["Pow"] != 0:
            # do nothing if HVAC is switched off
            _LOGGER.info("SyncState with SwUpDn=" + str(swing_mode))
            self.SyncState({"SwUpDn": self._swing_modes.index(swing_mode)})
            self.schedule_update_ha_state()

    def set_preset_mode(self, preset_mode):
        if self._acOptions["Pow"] != 0:
            # do nothing if HVAC is switched off
            _LOGGER.info("SyncState with SwingLfRig=" + str(preset_mode))
            self.SyncState({"SwingLfRig": self._preset_modes.index(preset_mode)})
            self.schedule_update_ha_state()

    def set_fan_mode(self, fan):
        _LOGGER.info("set_fan_mode(): " + str(fan))
        # Set the fan mode.
        if self._acOptions["Pow"] != 0:
            if fan.lower() == "turbo":
                _LOGGER.info("Enabling turbo mode")
                self.SyncState({"Tur": 1, "Quiet": 0})
            elif fan.lower() == "quiet":
                _LOGGER.info("Enabling quiet mode")
                self.SyncState({"Tur": 0, "Quiet": 1})
            else:
                _LOGGER.info(
                    "Setting normal fan mode to " + str(self._fan_modes.index(fan))
                )
                self.SyncState(
                    {"WdSpd": str(self._fan_modes.index(fan)), "Tur": 0, "Quiet": 0}
                )
            self.schedule_update_ha_state()

    def set_hvac_mode(self, hvac_mode):
        _LOGGER.info("set_hvac_mode(): " + str(hvac_mode))
        # Set new operation mode.
        c = {}
        if hvac_mode == HVACMode.OFF:
            c.update({"Pow": 0})
            if hasattr(self, "_auto_light") and self._auto_light:
                c.update({"Lig": 0})
                if (
                    hasattr(self, "_has_light_sensor")
                    and self._has_light_sensor
                    and hasattr(self, "_enable_light_sensor")
                    and self._enable_light_sensor
                ):
                    c.update({"LigSen": 1})
        else:
            c.update({"Pow": 1, "Mod": self.hvac_modes.index(hvac_mode)})
            if hasattr(self, "_auto_light") and self._auto_light:
                c.update({"Lig": 1})
                if (
                    hasattr(self, "_has_light_sensor")
                    and self._has_light_sensor
                    and hasattr(self, "_enable_light_sensor")
                    and self._enable_light_sensor
                ):
                    c.update({"LigSen": 0})
            if hasattr(self, "_auto_xfan") and self._auto_xfan:
                if (hvac_mode == HVACMode.COOL) or (hvac_mode == HVACMode.DRY):
                    c.update({"Blo": 1})
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_on(self):
        _LOGGER.info("turn_on(): ")
        # Turn on.
        c = {"Pow": 1}
        if hasattr(self, "_auto_light") and self._auto_light:
            c.update({"Lig": 1})
            if (
                hasattr(self, "_has_light_sensor")
                and self._has_light_sensor
                and hasattr(self, "_enable_light_sensor")
                and self._enable_light_sensor
            ):
                c.update({"LigSen": 0})
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_off(self):
        _LOGGER.info("turn_off(): ")
        # Turn off.
        c = {"Pow": 0}
        if hasattr(self, "_auto_light") and self._auto_light:
            c.update({"Lig": 0})
            if (
                hasattr(self, "_has_light_sensor")
                and self._has_light_sensor
                and hasattr(self, "_enable_light_sensor")
                and self._enable_light_sensor
            ):
                c.update({"LigSen": 1})
        self.SyncState(c)
        self.schedule_update_ha_state()

    async def async_added_to_hass(self):
        _LOGGER.info("Gree climate device added to hass()")
        self.update()
