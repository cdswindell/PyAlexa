# -*- coding: utf-8 -*-

#
# PyTrain/My Layout Alexa Skill
#
# The My Layout skill translates your voice commands into Lionel TMCC and Legacy commands
# to control engines, trains, switches, and other equipment. The skill communicates
# via HTTPS with a PyTrain API Server on your local network with access to your Base 3.
#
from __future__ import annotations

import logging
import os
import socket
from os.path import join, dirname
from typing import Any

import ask_sdk_core.utils as ask_utils
import boto3
import jwt
import requests
from ask_sdk_core.dispatch_components import AbstractExceptionHandler
from ask_sdk_core.dispatch_components import AbstractRequestHandler
from ask_sdk_core.handler_input import HandlerInput
from ask_sdk_core.skill_builder import CustomSkillBuilder
from ask_sdk_core.utils.request_util import get_user_id
from ask_sdk_dynamodb.adapter import DynamoDbAdapter
from ask_sdk_model import Response, Slot, IntentRequest, Intent, IntentConfirmationStatus, DialogState
from ask_sdk_model.dialog import ElicitSlotDirective
from ask_sdk_model.slu.entityresolution.status_code import StatusCode
from dotenv import load_dotenv
from isodate import parse_duration

dotenv_path = join(dirname(__file__), ".env")
load_dotenv(dotenv_path)

SECRET_PHRASE = os.environ.get("SECRET_PHRASE")
ALGORITHM = os.environ.get("ALGORITHM")
LOGGER_LEVEL = os.environ.get("LOGGER_LEVEL", "INFO").upper()

logger = logging.getLogger(__name__)
logger.setLevel(level=LOGGER_LEVEL)

SKILL_NAME = "My Layout"
REQUEST_SERVER_OUTPUT = f"""
    Welcome to {SKILL_NAME}! To get started, please tell me your
    PyTrain API server URL. Please say: 'My PyTrain server is',
    followed by your server's URL or IP Address.
    Use the word 'dot' for periods.
"""

REQUEST_SERVER_REPROMPT = "Please say: 'My PyTrain Server is', followed by the name of your server's URL."

PYTRAIN_REPROMPT = f"For {SKILL_NAME} help, say 'help!"

PATH_MAP = {
    "0": "engine",
    "1": "train",
    "2": "switch",
    "3": "accessory",
    "4": "route",
}

MOMENTUM_MAP = {
    "0": "low",
    "1": "low plus",
    "2": "medium low",
    "3": "medium",
    "5": "medium high",
    "7": "high",
}

#
# initialize persistence adapter
ddb_resource = boto3.resource("dynamodb")
ddb_table_name = os.environ.get("DYNAMODB_PERSISTENCE_TABLE_NAME")
ddb_table_name = ddb_table_name if ddb_table_name else "pytrain-skill-state"
dynamodb_adapter = DynamoDbAdapter(table_name=ddb_table_name, create_table=True, dynamodb_resource=ddb_resource)


class NoServerException(Exception):
    pass


class ServerNotRespondingException(Exception):
    def __init__(self, server: str, protocol: str) -> None:
        message = f"Error connecting to {protocol} {server}"
        super().__init__(message)
        self.server = server
        self.protocol = protocol


class ApiTokenExpiredException(Exception):
    pass


class UnsupportedDurationException(Exception):
    def __init__(self, duration: Any) -> None:
        message = f"Duration not supported: {duration}"
        super().__init__(message)
        self.duration = duration


def get_state(handler_input) -> dict:
    state = handler_input.attributes_manager.session_attributes
    if state is None or state.get("URL_BASE", None) is None:
        state = handler_input.attributes_manager.persistent_attributes
        if not state:
            state["server"] = None
            state["URL_BASE"] = None
            state["invocations"] = 0
            handler_input.attributes_manager.save_persistent_attributes()
        handler_input.attributes_manager.session_attributes = state
    return state


def persist_state(handler_input, state: dict[str, Any]):
    if handler_input.attributes_manager.session_attributes:
        session_state = handler_input.attributes_manager.session_attributes
        persisted_state = session_state.copy()
    else:
        persisted_state = {}
        handler_input.attributes_manager.session_attributes = session_state = {}
    deleted_keys = set()
    for k, v in state.items():
        if v is None:
            deleted_keys.add(k)
        else:
            session_state[k] = v
            if k not in {"api-key", "uid", "last-url"}:
                persisted_state[k] = v
    # don't persist deleted keys
    if deleted_keys:
        persisted_state = {k: v for k, v in persisted_state.items() if k not in deleted_keys}
    handler_input.attributes_manager.session_attributes = persisted_state
    handler_input.attributes_manager.persistent_attributes = persisted_state.copy()
    for key in ["api-key", "last-url"]:
        if key in persisted_state:
            del handler_input.attributes_manager.persistent_attributes[key]
    handler_input.attributes_manager.save_persistent_attributes()


def get_user_info(handler_input) -> dict:
    """
    This function is currently deprecated. Leaving here for reference.
    """
    # Fetching access token
    access_token = str(handler_input.request_envelope.context.system.api_access_token)
    api_access_token = "Bearer " + access_token
    headers = {"Authorization": api_access_token}
    user_info = {"uid": get_user_id(handler_input)}
    for pc in ["email", "givenName"]:
        # Fetching user profile from ASK API
        ep = f"https://api.amazonalexa.com/v2/accounts/~current/settings/Profile.{pc}"
        r = requests.get(ep, headers=headers)
        if r.status_code == 200:
            user_info[pc] = r.json()
    persist_state(handler_input, user_info)
    return user_info


def encrypt_request(state, server: str = None) -> str:
    uid = state.get("uid")
    server = server if server else state.get("server")
    return jwt.encode({"UID": uid, "SERVER": server, "magic": "alexa"}, server, algorithm=ALGORITHM)


def request_api_key(
    handler_input,
    state=None,
    server: str = None,
    protocol: str = None,
    check_accessible: bool = True,
) -> requests.Response:
    # get_user_info(handler_input)
    state = state if state else get_state(handler_input)
    server = server if server else state.get("server", None)
    protocol = protocol if protocol else state.get("protocol", "http")
    if check_accessible is True and is_server_accessible(state) is False:
        raise ServerNotRespondingException(server, protocol)
    response = requests.post(f"{protocol}://{server}/version", json={"uid": encrypt_request(state, server=server)})
    if response.status_code == 200:
        state["api-key"] = response.json().get("api-token", None)
        persist_state(handler_input, state)
    return response


def get_canonical_slot(slot):
    if slot and slot.resolutions and slot.resolutions.resolutions_per_authority:
        for resolution in slot.resolutions.resolutions_per_authority:
            if resolution.status and resolution.status.code == StatusCode.ER_SUCCESS_MATCH:
                return resolution.values[0]
    return None


def is_server_accessible(state: dict):
    """
    Checks if a server is accessible at the given host and port.

    Args:
        state (dict): session state, containing host name and protocol.

    Returns:
        bool: True if the server is accessible, False otherwise.
    """
    host = state.get("server", None)
    port = 443 if state.get("protocol", "http") == "https" else 80
    if not host:
        return False
    logger.debug(f"Checking connectivity to {host}:{port}...")
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        s.settimeout(5)
        # Attempt to connect to the server
        s.connect((host, port))
        # Close the socket
        s.close()
        logger.debug(f"{host}:{port} is accessible...")
        return True
    except socket.error as se:
        logger.warning(f"Error connecting to {host}:{port} - {se}")
        return False
    except Exception as e:
        logger.warning(f"Error connecting to {host}:{port} - {e}")
        return False


class LaunchRequestHandler(AbstractRequestHandler):
    """Handler for Skill Launch."""

    def can_handle(self, handler_input: HandlerInput) -> bool:
        return ask_utils.is_request_type("LaunchRequest")(handler_input)

    def handle(self, handler_input: HandlerInput) -> Response:
        state = get_state(handler_input)
        if state and state.get("URL_BASE", None) and state.get("server", None):
            if is_server_accessible(state):
                speak_output = f"Welcome back to {SKILL_NAME}!"
                reprompt = PYTRAIN_REPROMPT
                state["invocations"] = state["invocations"] + 1 if "invocations" in state else 1
                if "engine" in state:
                    state["engine"] = None
                logger.debug("Requesting API Key...")
                try:
                    response: requests.Response = request_api_key(handler_input, state)
                    if response.status_code != 200:
                        logger.warning(f"Launch request failed with status code: {response.status_code} {response}")
                        speak_output = (
                            "Oh dear, I've hit a snag! Is your PyTrain API server active? If so, try resetting it; "
                            + f"Error code {response.status_code} "
                            + REQUEST_SERVER_REPROMPT
                        )
                        reprompt = REQUEST_SERVER_REPROMPT

                except Exception as e:
                    logger.error(e)
                    raise e
            else:
                raise ServerNotRespondingException(state.get("server"), state.get("protocol"))
        else:
            speak_output = REQUEST_SERVER_OUTPUT
            reprompt = REQUEST_SERVER_REPROMPT
        return handler_input.response_builder.speak(speak_output).ask(reprompt).set_should_end_session(False).response


class PyTrainIntentHandler(AbstractRequestHandler):
    _slots = None
    _handler_input = None
    _intent = None

    def can_handle(self, handler_input: HandlerInput) -> bool:
        self._intent = intent = self.__class__.__name__.replace("Handler", "")
        return ask_utils.is_intent_name(intent)(handler_input)

    def handle(self, handler_input: HandlerInput, raise_exception: bool = True) -> Response | None:
        setattr(self, "_handler_input", handler_input)
        request = handler_input.request_envelope.request
        if isinstance(request, IntentRequest):
            setattr(self, "_slots", request.intent.slots)
            state = self.session_state
            if (
                request.dialog_state == DialogState.STARTED
                and self.engine_slot is not None
                and self.engine_slot.value is None
                and state.get("engine", None) is None
            ):
                directive = ElicitSlotDirective(
                    slot_to_elicit="engine",
                    updated_intent=Intent(
                        name=self.intent,
                        confirmation_status=IntentConfirmationStatus.NONE,
                        slots=request.intent.slots,
                    ),
                )
                speak_output = f"What's the TMCC ID of the {self.scope} you want to control?"
                ask_output = "What's the TMCC ID?"
                return (
                    handler_input.response_builder.add_directive(directive)
                    .speak(speak_output)
                    .ask(ask_output)
                    .set_should_end_session(False)
                    .response
                )
                # raise DialogIncompleteException(self)
        if raise_exception is True:
            state = self.session_state
            if state is None or state.get("URL_BASE", None) is None or state.get("server", None) is None:
                raise NoServerException
            if state.get("api-key", None) is None:
                response: requests.Response = request_api_key(handler_input, state=state)
                if response and response.status_code != 200:
                    logger.warning(f"Handler Super Request failed with status code: {response.status_code} {response}")
        return None

    def handle_response(
        self,
        response: requests.Response | str | None,
        handler_input,
        speak_output,
        reprompt="What next?",
        close_session: bool = False,
        default_responses: bool = True,
    ):
        if isinstance(response, requests.Response):
            if response.status_code == 200:
                # Handle the response data
                resp_dict = response.json()
                if "api-token" in resp_dict:
                    resp_dict["api-token"] = "<*** Secret API Token ***>"
                logger.debug(resp_dict)
            elif response.status_code == 498:
                # get a new token and repeat the last API call
                state = self.session_state
                if "api-key" in state:
                    del state["api-key"]
                if "last-url" in state:
                    del state["last-url"]
                    return self.handle(handler_input)  # get new API Token
                raise ApiTokenExpiredException()
            elif default_responses is True and 400 <= response.status_code <= 499:
                speak_output = None
                if response.status_code == 422:
                    data = response.json()
                    if data:
                        speak_output = data.get("detail", None)
                if speak_output is None:
                    speak_output = (
                        f"I'm afraid you're not authorized to use {SKILL_NAME}, good-bye. Error: {response.status_code}"
                    )
                    reprompt = None
                    close_session = True
            else:
                logger.warning(f"Request failed with status code: {response.status_code}")
        elif isinstance(response, str) and response == "ok":
            pass
        else:
            logger.warning("Request failed with no additional information")
        return (
            handler_input.response_builder.speak(speak_output)
            .ask(reprompt)
            .set_should_end_session(close_session)
            .response
        )

    def last_url(self, url: str, method: str) -> None:
        state = get_state(self._handler_input)
        if state:
            state["last-url"] = {"url": url, "method": method}

    def post(self, url: str) -> requests.Response:
        logger.debug(f"POST URL: {url}")
        self.last_url(url, "POST")
        headers = {"X-API-Key": self.api_key}
        return requests.post(url, headers=headers)

    def get(self, url: str) -> requests.Response:
        logger.debug(f"GET URL: {url}")
        self.last_url(url, "GET")
        headers = {"X-API-Key": self.api_key}
        return requests.get(url, headers=headers)

    @property
    def session_state(self) -> dict:
        state = self._handler_input.attributes_manager.session_attributes
        if state is None or "URL_BASE" not in state or "server" not in state or "api-key" not in state:
            state = get_state(self._handler_input)
        return state

    @property
    def api_key(self) -> str:
        return self.session_state.get("api-key")

    @property
    def scope(self) -> str:
        """
        Get scope slot. If not present or empty, use persisted value
        """
        state = self.session_state
        slots = self._handler_input.request_envelope.request.intent.slots
        scope = get_canonical_slot(slots["scope"]) if slots and "scope" in slots else None
        if scope is None or not scope.value:
            scope = state.get("scope", "engine")
        else:
            scope = "train" if scope and scope.value and scope.value.id == "1" else "engine"
            if scope != state.get("scope", None):
                persist_state(self._handler_input, {"scope": scope})
        return scope

    @property
    def component(self) -> str:
        scope = get_canonical_slot(self._slots["scope_ex"]) if "scope_ex" in self._slots else None
        if scope:
            return PATH_MAP.get(scope.value.id, "engine")
        else:
            return "engine"

    @property
    def bell(self):
        return get_canonical_slot(self._slots["ring"]) if "ring" in self._slots else None

    @property
    def coupler(self):
        return get_canonical_slot(self._slots["coupler"]) if "coupler" in self._slots else None

    @property
    def dialog(self):
        slots = self._handler_input.request_envelope.request.intent.slots
        return get_canonical_slot(slots["dialog"]) if "dialog" in slots else None

    @property
    def direction(self):
        return get_canonical_slot(self._slots["direction"]) if "direction" in self._slots else None

    @property
    def duration(self) -> int | None:
        slots = self._handler_input.request_envelope.request.intent.slots
        duration_slot = slots["duration"] if "duration" in slots else None
        if duration_slot is not None and duration_slot.value:
            if duration_slot.value.startswith("PT"):
                duration = parse_duration(duration_slot.value).seconds
                if duration > 120:
                    raise UnsupportedDurationException(duration_slot.value)
            else:
                raise UnsupportedDurationException(duration_slot.value)
        else:
            duration = None
        return duration

    @property
    def engine_slot(self) -> Slot:
        slots = self._handler_input.request_envelope.request.intent.slots
        return slots["engine"] if slots and "engine" in slots else None

    @property
    def engine(self) -> int | None:
        """
        Get engine address. If not specified, use persisted value
        """
        engine_slot = self.engine_slot
        state = self.session_state
        engine_addr = engine_slot.value if engine_slot and engine_slot.value else state.get("engine", None)
        if engine_addr and engine_addr != state.get("engine", None):
            persist_state(self._handler_input, {"engine": engine_addr})
        return engine_addr

    @property
    def horn(self):
        return get_canonical_slot(self._slots["horn"]) if "horn" in self._slots else None

    @property
    def intent(self):
        return self._intent

    @property
    def momentum(self):
        slots = self._handler_input.request_envelope.request.intent.slots
        return get_canonical_slot(slots["momentum"]) if "momentum" in slots else None

    @property
    def on_off(self):
        return get_canonical_slot(self._slots["state"]) if "state" in self._slots else None

    @property
    def protocol(self) -> str:
        prot = get_canonical_slot(self._slots["protocol"]) if "protocol" in self._slots else None
        logger.info(f"Protocol: {prot} {prot.value.name if prot else ''}")
        return prot.value.name if prot else "http"

    @property
    def smoke(self):
        return get_canonical_slot(self._slots["smoke"]) if "smoke" in self._slots else None

    @property
    def speed(self):
        return get_canonical_slot(self._slots["speed"]) if "speed" in self._slots else None

    @property
    def tmcc_id(self):
        return self._slots["tmcc_id"] if "tmcc_id" in self._slots else self.engine_slot

    @property
    def url_base(self) -> str:
        return self.session_state.get("URL_BASE")

    @property
    def volume(self):
        return get_canonical_slot(self._slots["volume"]) if "volume" in self._slots else None


class ResetApiServerIntentHandler(PyTrainIntentHandler):
    def handle(self, handler_input: HandlerInput, raise_exception: bool = False) -> Response:
        super().handle(handler_input, raise_exception)
        persist_state(
            handler_input,
            {
                "URL_BASE": None,
                "server": None,
                "protocol": None,
                "engine": None,
                "scope": None,
            },
        )
        speak_output = REQUEST_SERVER_OUTPUT
        reprompt = REQUEST_SERVER_REPROMPT
        return handler_input.response_builder.speak(speak_output).ask(reprompt).set_should_end_session(False).response


class SetPyTrainServerIntentHandler(PyTrainIntentHandler):
    def handle(self, handler_input: HandlerInput, raise_exception: bool = False) -> Response:
        super().handle(handler_input, raise_exception)
        state = get_state(handler_input)
        server = self._slots["server"].value if "server" in self._slots else None
        parts = server.split()
        new_parts = []
        http = ""
        for part in parts:
            part = part.lower().replace("://", "").strip()
            if not part or part in ["colon", "slash", "", "://", ":", "/"]:
                continue
            if part == "dot":
                new_parts.append(".")
            elif part in ["http", "https"]:
                http = part
            else:
                new_parts.append(part)
        processed = "".join(new_parts).strip()
        if processed and processed != "none":
            logger.info(f"Setting PyTrain URL Server: {server} Processed: {processed}")
            response = request_api_key(
                handler_input,
                state=state,
                server=processed,
                protocol=http,
                check_accessible=False,
            )
            if response and response.status_code == 200:
                speak_output = f"Setting PyTrain server URL to {server}"
                reprompt = PYTRAIN_REPROMPT
                http = http if http else "http"
                url_base = f"{http}://{processed}/pytrain/v1"
                persist_state(
                    handler_input,
                    {
                        "URL_BASE": url_base,
                        "server": processed,
                        "protocol": http,
                        "engine": None,
                        "scope": None,
                    },
                )
            else:
                logger.warning(f"Failed to set Server URL: {response}")
                speak_output = (
                    f"There was a problem connecting to {processed}, please try again Error {response.status_code}"
                )
                reprompt = REQUEST_SERVER_REPROMPT
        else:
            logger.warning(f"No Server Specified: '{server} {processed} {type(processed)}'")
            speak_output = REQUEST_SERVER_REPROMPT
            reprompt = REQUEST_SERVER_REPROMPT
            response = "ok"
        return self.handle_response(
            response,
            handler_input,
            speak_output,
            reprompt=reprompt,
            default_responses=False,
        )


class HaltIntentHandler(PyTrainIntentHandler):
    """Handler for Halt Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        url = f"{self.url_base}/system/halt"
        speak_output = "Halting all trains"
        response = self.get(url)
        return self.handle_response(response, handler_input, speak_output)


class SpeedIntentHandler(PyTrainIntentHandler):
    """Handler for Speed Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        speed = self.speed
        dialog = self.dialog
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} you want me to control, sorry!"
        elif speed is None or speed.value is None:
            logger.warning(f"Invalid speed: {speed}")
            speak_output = f"You specified an invalid speed for {scope} {engine}, please try again."
            response = "ok"
        else:
            opt = ""
            if dialog is not None:
                if dialog.value.id == "1":
                    opt = "?dialog=true"
                elif dialog.value.id == "2":
                    opt = "?immediate=true"
            speed_val = speed.value.id if speed else "0"
            url = f"{self.url_base}/{scope}/{engine}/speed_req/{speed_val}{opt}"
            speak_output = f"Changing the speed of {scope} {engine} to speed step {speed.value.name}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class BoostSpeedIntentHandler(PyTrainIntentHandler):
    """Handler for Boost Speed Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        duration = self.duration
        if engine is None:
            logger.warning("No Engine Specified")
            speak_output = f"I don't know what {scope} you want me to boost, sorry!"
        else:
            dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
            dur_param = f"?duration={duration}" if duration else ""
            url = f"{self.url_base}/{scope}/{engine}/boost_req{dur_param}"
            speak_output = f"Boosting speed on {scope} {engine}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class BrakeSpeedIntentHandler(PyTrainIntentHandler):
    """Handler for Brake Speed Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        duration = self.duration
        if engine is None:
            logger.warning("No Engine Specified")
            speak_output = f"I don't know what {scope} you want me to brake, sorry!"
        else:
            dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
            dur_param = f"?duration={duration}" if duration else ""
            url = f"{self.url_base}/{scope}/{engine}/brake_req{dur_param}"
            speak_output = f"Braking speed on {scope} {engine}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class OpenCouplerIntentHandler(PyTrainIntentHandler):
    """Handler for Open Coupler Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        coupler = self.coupler
        if engine is None:
            logger.warning(f"No {scope} number specified")
            speak_output = f"I don't know what {scope} you want me to decouple, sorry!"
        else:
            if coupler and coupler.value.id == "1":
                url = f"{self.url_base}/{scope}/{engine}/rear_coupler_req"
                device = "rear"
            else:
                url = f"{self.url_base}/{scope}/{engine}/front_coupler_req"
                device = "front"
            speak_output = f"Opening {device} coupler on {scope} {engine}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class SoundHornIntentHandler(PyTrainIntentHandler):
    """Handler for Sound Horn Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        horn = self.horn
        duration = self.duration
        if engine is None:
            logger.warning(f"No {scope} Specified")
            speak_output = f"I don't know what {scope} you want me to sound, sorry!"
        else:
            opt = "sound"
            device = "horn"
            dur = dur_param = ""
            if horn is not None:
                if horn.value.id == "2":
                    opt = "grade"
                    device = "crossing signal"
                else:
                    if horn.value.id == "1":
                        device = "whistle"
                    if duration:
                        dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
                        dur_param = f"&duration={duration}"
            url = f"{self.url_base}/{scope}/{engine}/horn_req?option={opt}{dur_param}"
            speak_output = f"Sounding {device} on {scope} {engine}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class RingBellIntentHandler(PyTrainIntentHandler):
    """Handler for Ring Bell Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        bell = self.bell
        duration = self.duration
        if engine is None:
            logger.warning("No Engine Specified")
            speak_output = f"I don't know what {scope} you want me to ring, sorry!"
        else:
            opt = "toggle"
            device = "Toggle bell"
            dur = dur_param = ""
            if bell is not None:
                if bell.value.id == "1":
                    opt = "once"
                    device = "Ring the bell once"
                    dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
                    dur_param = f"&duration={duration}" if duration else ""
                elif bell.value.id == "2":
                    opt = "on"
                    device = "Enable the bell"
                elif bell.value.id == "3":
                    opt = "off"
                    device = "Disable the bell"
            url = f"{self.url_base}/{scope}/{engine}/bell_req?option={opt}{dur_param}"
            speak_output = f"{device} on {scope} {engine}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class StartUpShutDownIntentHandler(PyTrainIntentHandler):
    """Handler for Start Up/Shut Down Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        on_off = self.on_off
        scope = self.scope
        engine = self.engine
        dialog = self.dialog
        if engine is None:
            logger.warning("No Engine/Train Number Specified")
            speak_output = f"I don't know what {scope} you want me to control, sorry!"
        elif on_off and on_off.value.id == "1":
            opt = "" if dialog is None or dialog.value.id == "0" else "?dialog=true"
            url = f"{self.url_base}/{scope}/{engine}/startup_req{opt}"
            speak_output = f"Starting up {scope} {engine}"
            response = self.post(url)
        else:
            opt = "" if dialog is None or dialog.value.id == "0" else "?dialog=true"
            url = f"{self.url_base}/{scope}/{engine}/shutdown_req{opt}"
            speak_output = f"Shutting down {scope} {engine}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class StopImmediateIntentHandler(PyTrainIntentHandler):
    """Handler for Stop Immediate Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} you want me to stop, sorry!"
        else:
            url = f"{self.url_base}/{scope}/{engine}/stop_req"
            speak_output = f"<speak>Stopping {scope} {engine} "
            speak_output += "<voice name='Brian'><lang xml:lang='en-GB'>in it's tracks!</lang></voice></speak>"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class ResetIntentHandler(PyTrainIntentHandler):
    @property
    def url(self):
        return f"{self.url_base}/{self.scope}/{self.engine}/reset_req"

    @property
    def spoken_response(self):
        return f"Resetting {self.scope} {self.engine}"

    """Handler for Reset Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} you want me to reset, sorry!"
        else:
            url = self.url
            speak_output = self.spoken_response
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class RefuelIntentHandler(ResetIntentHandler):
    @property
    def url(self):
        duration = self.duration if self.duration and self.duration >= 3 else 3
        return f"{self.url_base}/{self.scope}/{self.engine}/reset_req?hold=true&duration={duration}"

    @property
    def spoken_response(self):
        duration = self.duration
        dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
        return f"Refueling {self.scope} {self.engine}{dur}"


class SetDirectionIntentHandler(PyTrainIntentHandler):
    """Handler for Set Direction Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        dr = self.direction
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} to change the direction of, sorry!"
        else:
            if dr and dr.value.id == "1":
                url = f"{self.url_base}/{scope}/{engine}/reverse_req"
            elif dr and dr.value.id == "2":
                url = f"{self.url_base}/{scope}/{engine}/toggle_direction_req"
            else:
                url = f"{self.url_base}/{scope}/{engine}/forward_req"
            speak_output = f"Changing the direction of {scope} {engine} to {dr.value.name}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class MomentumIntentHandler(PyTrainIntentHandler):
    """Handler for momentum Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        mom = self.momentum
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} to change the momentum of, sorry!"
        elif mom is None or mom.value is None:
            speak_output = f"You specified an invalid momentum level for {scope} {engine}, please try again."
            response = "ok"
        else:
            mom_spk = MOMENTUM_MAP.get(mom.value.id, mom.value.id)
            url = f"{self.url_base}/{scope}/{engine}/momentum_req?level={mom.value.id}"
            speak_output = f"Changing the momentum of {scope} {engine} to {mom_spk}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class SequenceControlIntentHandler(PyTrainIntentHandler):
    """Handler for Sequence Control Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        on_off = self.on_off
        scope = self.scope
        engine = self.engine
        if engine is None:
            logger.warning("No Engine/Train Number Specified")
            speak_output = f"I don't know what {scope} you want me to control, sorry!"
        elif on_off and on_off.value.id == "1":
            url = f"{self.url_base}/{scope}/{engine}/aux1?duration=4.0"
            speak_output = f"Enabling sequence control on {scope} {engine}"
            response = self.post(url)
        else:
            url = f"{self.url_base}/{scope}/{engine}/aux1"
            response = self.post(url)
            if response and response.status_code == 200:
                url = f"{self.url_base}/{scope}/{engine}/numeric_req?number=0"
                response = self.post(url)
                speak_output = f"Disabling sequence control on {scope} {engine}"
            else:
                speak_output = f"I can't disable sequence control. Try saying 'reset {scope} {engine}'"
        return self.handle_response(response, handler_input, speak_output)


class PowerDistrictIntentHandler(PyTrainIntentHandler):
    """Handler for Power District Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        tmcc_id = self.tmcc_id
        on_off = self.on_off
        if tmcc_id is None:
            logger.warning("No power district TMCC ID Specified")
            speak_output = "I don't know what power district to control, sorry!"
        else:
            if on_off and on_off.value.id == "1":
                url = f"{self.url_base}/accessory/{tmcc_id.value}/bpc2_req?state=on"
            else:
                url = f"{self.url_base}/accessory/{tmcc_id.value}/bpc2_req?state=off"
            speak_output = f"Turning {on_off.value.name} power district {tmcc_id.value}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class AccessoryIntentHandler(PyTrainIntentHandler):
    """Handler for Accessory Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        tmcc_id = self.tmcc_id
        on_off = self.on_off
        duration = self.duration
        if tmcc_id is None:
            logger.warning("No accessory TMCC ID Specified")
            speak_output = "I don't know the accessory to control, sorry!"
        else:
            if duration:
                dur = f" for {duration} second{'s' if duration > 1 else ''}" if duration else ""
                dur_param = f"&duration={duration}" if duration else ""
            else:
                dur = dur_param = ""
            if on_off and on_off.value.id == "1":
                url = f"{self.url_base}/accessory/{tmcc_id.value}/asc2_req?state=on{dur_param}"
            else:
                dur = ""
                url = f"{self.url_base}/accessory/{tmcc_id.value}/asc2_req?state=off"
            speak_output = f"Turning {on_off.value.name} accessory {tmcc_id.value}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class ChangeVolumeIntentHandler(PyTrainIntentHandler):
    """Handler for Change Volume Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        vol = self.volume
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} to change the volume of, sorry!"
        else:
            if vol and vol.value.id == "1":
                url = f"{self.url_base}/{scope}/{engine}/volume_down_req"
                directive = "Decreasing"
            else:
                url = f"{self.url_base}/{scope}/{engine}/volume_up_req"
                directive = "Increasing"
            speak_output = f"{directive} the volume of {scope} {engine}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class SmokeLevelIntentHandler(PyTrainIntentHandler):
    """Handler for Smoke Level Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        response = super().handle(handler_input)
        if response:
            return response
        scope = self.scope
        engine = self.engine
        smoke = self.smoke
        if engine is None:
            logger.warning(f"No {scope} Number Specified")
            speak_output = f"I don't know what {scope} you want me to smoke, sorry!"
        elif smoke is None or smoke.value is None:
            logger.warning(f"Invalid smoke level: {smoke}")
            speak_output = f"You specified an invalid smoke level for {scope} {engine}, please try again."
            response = "ok"
        else:
            opt = "?level=off" if smoke is None or smoke.value.id == "0" else f"?level={smoke.value.name.lower()}"
            url = f"{self.url_base}/{scope}/{engine}/smoke_level_req{opt}"
            speak_output = f"Setting smoke level on {scope} {engine} to {smoke.value.name}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class ThrowSwitchIntentHandler(PyTrainIntentHandler):
    """Handler for Throw Switch Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        switch = self._slots["switch"] if "switch" in self._slots else None
        position = get_canonical_slot(self._slots["position"]) if "position" in self._slots else None
        if switch is None:
            logger.warning("No Switch Number Specified")
            speak_output = "I don't know what switch you want me to throw, sorry!"
        else:
            pos = "thru" if position is None or position.value.id == "0" else "out"
            url = f"{self.url_base}/switch/{switch.value}/{pos}_req"
            speak_output = f"Throwing switch {switch.value} {pos}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class FireRouteIntentHandler(PyTrainIntentHandler):
    """Handler for Fire Route Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        route = self._slots["route"] if "route" in self._slots else None
        if route is None:
            logger.warning("No Route Number Specified")
            speak_output = "I don't know the route to fire, sorry!"
        else:
            url = f"{self.url_base}/route/{route.value}/fire_req"
            speak_output = f"Firing route {route.value}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class GetStatusIntentHandler(PyTrainIntentHandler):
    """Handler for Get Status Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.component
        tmcc_id = self.tmcc_id
        if tmcc_id is None:
            logger.warning("No TMCC ID Specified")
            speak_output = f"I don't know the {scope} to query, sorry!"
        else:
            url = f"{self.url_base}/{scope}/{tmcc_id.value}"
            speak_output = f"Getting the status of {scope} {tmcc_id.value}"
            response = self.get(url)
            if response:
                if response.status_code == 200:
                    # Handle the response data
                    data = response.json()
                    speak_output = (
                        f"<speak>Here's the current status of {scope} {tmcc_id.value}: <break strength='strong'/>"
                    )
                    for key, value in data.items():
                        if value is None:
                            continue
                        if key == "scope":
                            continue
                        if key == "tmcc_id":
                            key = "TMCC <say-as interpret-as='spell-out'>ID</say-as>"
                        key = key.replace("_", " ")
                        if isinstance(value, str):
                            value = value.replace("_", " ")
                            value = value.replace("-", " ")
                            value = value.replace("&", " and ")
                        speak_output += f"{key}<break strength='medium'/> {value}<break strength='strong'/>"
                    speak_output += "</speak>"
                elif response.status_code == 404:
                    speak_output = f"I couldn't find any {scope} numbered {tmcc_id.value}"
                    response.status_code = 200
        return self.handle_response(response, handler_input, speak_output)


class FindTmccIdIntentHandler(PyTrainIntentHandler):
    """Handler for Find TMCC ID Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        # we don't want to persist the engine number, so get the value from the slot
        engine_slot = self.engine_slot
        engine_num = engine_slot.value if engine_slot else None
        if engine_num is None:
            logger.warning("No Engine Number Specified")
            speak_output = "I don't know the engine number to query, sorry!"
        else:
            engine_num = engine_num
            speak_output = ""
            url = f"{self.url_base}/engine/{engine_num}"
            response = self.get(url)
            if response is not None:
                if response.status_code == 200:
                    # Handle the response data
                    data = response.json()
                    tmcc_id = data.get("tmcc_id", None)
                    if tmcc_id:
                        speak_output = "<speak>The TMCC <say-as interpret-as='spell-out'>ID</say-as> "
                        speak_output += f"of Engine number {engine_num} is {tmcc_id}</speak>"
                    else:
                        speak_output = f"I couldn't find any engine numbered {engine_num}."
                elif response.status_code == 404:
                    speak_output = f"I couldn't find any engine numbered {engine_num}"
                    response.status_code = 200
        return self.handle_response(response, handler_input, speak_output)


class ProtocolIntentHandler(PyTrainIntentHandler):
    """Handler for Protocol Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input, raise_exception=False)
        state = self.session_state
        server = state.get("server", None)
        protocol = self.protocol
        if protocol:
            url_pase = f"{protocol}://{server}/pytrain/v1"
            persist_state(handler_input, {"protocol": protocol, "URL_BASE": url_pase})
            speak_output = f"Changing endpoint protocol to {protocol}"
        else:
            speak_output = "I've left the endpoint protocol alone"
        return self.handle_response("ok", handler_input, speak_output)


class HelpIntentHandler(AbstractRequestHandler):
    """Handler for Help Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = f"""
            <speak>{SKILL_NAME} lets you control your
            Lion<break strength='none'/><phoneme alphabet='ipa' ph='`ɛ:l'>el</phoneme>
            layout with your voice!<break strength='medium'/>
            Here are some examples of what you can say:<break strength='strong'/>

            <prosody rate='90%'>
            'Power up engine 67.',<break strength='strong'/>
            'Set the speed of engine 23 to slow.',<break strength='strong'/>
            'Blow the whistle on Engine 5 for 30 seconds.',<break strength='strong'/>
            "Reverse Engine sixty three.,<break strength='strong'/>
            'Reset engine five.',<break strength='strong'/>
            'Refuel train seventeen for 10 seconds.',<break strength='strong'/>
            'Shut down train 33.',<break strength='strong'/>
            'throw switch 5 to thru.'<break strength='strong'/>
            'fire route 10.'<break strength='strong'/>
            'Get status of engine 23.',<break strength='x-strong'/>
            </prosody>

            In cace of trouble, say:
                <amazon:emotion name="excited" intensity="medium">'Emergency Halt!'</amazon:emotion>,
            <break strength='x-strong'/>

            What would <emphasis level='strong'>you</emphasis> like to do?</speak>
            """

        return handler_input.response_builder.speak(speak_output).ask(speak_output).response


class CancelIntentHandler(AbstractRequestHandler):
    """Single handler for Cancel and Stop Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.CancelIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "Canceling."

        return (
            handler_input.response_builder.speak(speak_output)
            .ask(PYTRAIN_REPROMPT)
            .set_should_end_session(False)
            .response
        )


class FallbackIntentHandler(AbstractRequestHandler):
    """Handler for Fallback Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.FallbackIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = f"""
        I'm afraid I can't help you with that. Say 'Help' for {SKILL_NAME} help and to hear
        examples of what you can say.
        """
        return handler_input.response_builder.speak(speak_output).set_should_end_session(False).response


class StopIntentHandler(AbstractRequestHandler):
    """Handler for Stop Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.StopIntent")(handler_input)

    def handle(self, handler_input: HandlerInput) -> Response:
        speak_output = f"Goodbye from {SKILL_NAME}!"
        persist_state(handler_input, {"engine": None, "scope": None})
        return handler_input.response_builder.speak(speak_output).set_should_end_session(True).response


class SessionEndedRequestHandler(AbstractRequestHandler):
    """Handler for Session End."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input: HandlerInput) -> Response:
        # Any cleanup logic goes here.
        return handler_input.response_builder.response


class IntentReflectorHandler(AbstractRequestHandler):
    """The intent reflector is used for interaction model testing and debugging.
    It will simply repeat the intent the user said. You can create custom handlers
    for your intents by defining them above, then also adding them to the request
    handler chain below.
    """

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("IntentRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        intent_name = ask_utils.get_intent_name(handler_input)
        speak_output = "You just triggered " + intent_name + "."

        return (
            handler_input.response_builder.speak(speak_output)
            # .ask("add a reprompt if you want to keep the session open for the user to respond")
            .response
        )


class CatchAllExceptionHandler(AbstractExceptionHandler):
    """
    Generic error handling to capture any syntax or routing errors. If you receive an error
    stating the request handler chain is not found, you have not implemented a handler for
    the intent being invoked or included it in the skill builder below.
    """

    def can_handle(self, handler_input: HandlerInput, exception: Exception) -> bool:
        return True

    def handle(self, handler_input: HandlerInput, exception: Exception) -> Response:
        if isinstance(exception, NoServerException):
            speak_output = REQUEST_SERVER_OUTPUT
            ask_output = REQUEST_SERVER_REPROMPT
            end_session = False
        elif isinstance(exception, ApiTokenExpiredException):
            if "api-key" in handler_input.attributes_manager.session_attributes:
                del handler_input.attributes_manager.session_attributes["api-key"]
            speak_output = "Sorry, could you please repeat that?"
            ask_output = "Please repeat your last request."
            end_session = False
        elif isinstance(exception, UnsupportedDurationException):
            speak_output = f"{SKILL_NAME} only supports durations of up to 2 minutes. Please try again."
            ask_output = "try again?"
            end_session = False
        elif isinstance(exception, ServerNotRespondingException):
            speak_output = (
                f"I'm sorry, I can't reach your PyTrain Api server at {exception.protocol} "
                f"{exception.server}. Please check that the server is up and then try again."
            )
            ask_output = ""
            end_session = True
        else:
            logger.error(exception, exc_info=True)
            speak_output = "Sorry, I had trouble doing what you asked. Please try again."
            ask_output = "try again?"
            end_session = True
        return (
            handler_input.response_builder.speak(speak_output)
            .ask(ask_output)
            .set_should_end_session(end_session)
            .response
        )


# The SkillBuilder object acts as the entry point for your skill, routing all request and response
# payloads to the handlers above. Make sure any new handlers or interceptors you've
# defined are included below. The order matters - they're processed top to bottom.
sb = CustomSkillBuilder(persistence_adapter=dynamodb_adapter)

sb.add_request_handler(LaunchRequestHandler())

sb.add_request_handler(AccessoryIntentHandler())
sb.add_request_handler(BoostSpeedIntentHandler())
sb.add_request_handler(BrakeSpeedIntentHandler())
sb.add_request_handler(ChangeVolumeIntentHandler())
sb.add_request_handler(FindTmccIdIntentHandler())
sb.add_request_handler(FireRouteIntentHandler())
sb.add_request_handler(GetStatusIntentHandler())
sb.add_request_handler(HaltIntentHandler())
sb.add_request_handler(MomentumIntentHandler())
sb.add_request_handler(OpenCouplerIntentHandler())
sb.add_request_handler(PowerDistrictIntentHandler())
sb.add_request_handler(ProtocolIntentHandler())
sb.add_request_handler(RefuelIntentHandler())
sb.add_request_handler(ResetIntentHandler())
sb.add_request_handler(RingBellIntentHandler())
sb.add_request_handler(SequenceControlIntentHandler())
sb.add_request_handler(SetDirectionIntentHandler())
sb.add_request_handler(SmokeLevelIntentHandler())
sb.add_request_handler(SetPyTrainServerIntentHandler())
sb.add_request_handler(StartUpShutDownIntentHandler())
sb.add_request_handler(SoundHornIntentHandler())
sb.add_request_handler(SpeedIntentHandler())
sb.add_request_handler(StopImmediateIntentHandler())
sb.add_request_handler(ThrowSwitchIntentHandler())
sb.add_request_handler(ResetApiServerIntentHandler())

sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelIntentHandler())
sb.add_request_handler(FallbackIntentHandler())
sb.add_request_handler(StopIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())

# make sure IntentReflectorHandler is last so it doesn't override your custom intent handlers
sb.add_request_handler(IntentReflectorHandler())
sb.add_exception_handler(CatchAllExceptionHandler())

handler = sb.lambda_handler()
