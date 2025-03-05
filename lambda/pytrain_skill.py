# -*- coding: utf-8 -*-

#
# PyTrain Alexa Skill
#
# The PyTrain skill translates your voice commands into Lionel TMCC and Legacy commands
# to control engines, trains, switches, and other equipment. The skill communicates
# via HTTPS with a PyTrain API Server on your local network with access to your Base 3.
#
import logging
import os
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
from ask_sdk_model import Response
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

REQUEST_SERVER_OUTPUT = """
    Welcome to PyTrain! To get started, I need to know your
    PyTrain API server URL. Please say: 'My PyTrain server is',
    followed by your server's URL. Use the word 'dot' for periods.
    Say 'HTTPS colon slash slash' and your URL to use HTTPS.'
"""

REQUEST_SERVER_REPROMPT = "Please say: 'My PyTrain Server is', followed by the name of your server's URL."

PYTRAIN_REPROMPT = "For PyTrain help, say 'help!"

PATH_MAP = {
    "0": "engine",
    "1": "train",
    "2": "switch",
    "3": "accessory",
    "4": "route",
}

#
# initialize persistence adapter
ddb_resource = boto3.resource("dynamodb")
ddb_table_name = os.environ.get("DYNAMODB_PERSISTENCE_TABLE_NAME")
ddb_table_name = ddb_table_name if ddb_table_name else "pytrain-skill-state"
dynamodb_adapter = DynamoDbAdapter(table_name=ddb_table_name, create_table=True, dynamodb_resource=ddb_resource)


class NoServerException(Exception):
    pass


class ApiTokenExpiredException(Exception):
    pass


class UnsupportedDuration(Exception):
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
    for k, v in state.items():
        session_state[k] = v
        if k not in ["api-key", "uid"]:
            persisted_state[k] = v
    handler_input.attributes_manager.persistent_attributes = persisted_state.copy()
    if "api-key" in persisted_state:
        del handler_input.attributes_manager.persistent_attributes["api-key"]
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


def encode_id(state, server: str = None) -> str:
    uid = state.get("uid")
    server = server if server else state.get("server")
    return jwt.encode({"UID": uid, "SERVER": server, "magic": "alexa"}, server, algorithm=ALGORITHM)


def request_api_key(handler_input, state=None, server: str = None) -> requests.Response:
    # get_user_info(handler_input)
    state = state if state else get_state(handler_input)
    server = server if server else state.get("server", None)
    response = requests.post(f"https://{server}/version", json={"uid": encode_id(state, server=server)})
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


class LaunchRequestHandler(AbstractRequestHandler):
    """Handler for Skill Launch."""

    def can_handle(self, handler_input: HandlerInput) -> bool:
        return ask_utils.is_request_type("LaunchRequest")(handler_input)

    def handle(self, handler_input: HandlerInput) -> Response:
        state = get_state(handler_input)
        if state and state.get("URL_BASE", None):
            speak_output = "Welcome back to PyTrain!"
            reprompt = PYTRAIN_REPROMPT
            state["invocations"] = state["invocations"] + 1 if "invocations" in state else 1
            response: requests.Response = request_api_key(handler_input, state)
            if response.status_code != 200:
                logger.warning(f"Launch Request failed with status code: {response.status_code} {response}")
                speak_output = (
                        "Oh dear, I've hit a snag! Is your PyTrain API server active? If so, try resetting it; "
                        + REQUEST_SERVER_REPROMPT
                )
                reprompt = REQUEST_SERVER_REPROMPT
        else:
            speak_output = REQUEST_SERVER_OUTPUT
            reprompt = REQUEST_SERVER_REPROMPT
        return handler_input.response_builder.speak(speak_output).ask(reprompt).set_should_end_session(False).response


class PyTrainIntentHandler(AbstractRequestHandler):
    _slots = None
    _handler_input = None

    def can_handle(self, handler_input: HandlerInput) -> bool:
        intent = self.__class__.__name__.replace("Handler", "")
        return ask_utils.is_intent_name(intent)(handler_input)

    def handle(self, handler_input: HandlerInput, raise_exception: bool = True) -> Response | None:
        setattr(self, "_handler_input", handler_input)
        setattr(self, "_slots", handler_input.request_envelope.request.intent.slots)
        if raise_exception is True:
            state = self.session_state
            if state is None or state.get("URL_BASE", None) is None:
                raise NoServerException
            if state.get("api-key", None) is None:
                response: requests.Response = request_api_key(handler_input, state=state)
                if response and response.status_code != 200:
                    logger.warning(f"Handler Super Request failed with status code: {response.status_code} {response}")
        return None

    def handle_response(
            self,
            response,
            handler_input,
            speak_output,
            reprompt="What next?",
            close_session: bool = False,
            default_responses: bool = True,
    ):
        if response is not None:
            if response.status_code == 200:
                # Handle the response data
                data = response.json()
                logger.debug(data)
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
                speak_output = (
                    f"I'm afraid you are not authorized to use PyTrain, good-bye. Error: {response.status_code}"
                )
                reprompt = None
                close_session = True
            else:
                logger.warning(f"Request failed with status code: {response.status_code}")
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
        if state is None or "URL_BASE" not in state or "api-key" not in state:
            state = get_state(self._handler_input)
        return state

    @property
    def api_key(self) -> str:
        return self.session_state.get("api-key")

    @property
    def url_base(self) -> str:
        return self.session_state.get("URL_BASE")

    @property
    def scope(self) -> str:
        slots = self._handler_input.request_envelope.request.intent.slots
        scope = get_canonical_slot(slots["scope"]) if "scope" in slots else None
        return "train" if scope and scope.value.id == "1" else "engine"

    @property
    def component(self) -> str:
        scope = get_canonical_slot(self._slots["scop_ex"]) if "scope_ex" in self._slots else None
        if scope:
            return PATH_MAP.get(scope.value.id, "engine")
        else:
            return "engine"

    @property
    def engine(self):
        slots = self._handler_input.request_envelope.request.intent.slots
        return slots["engine"] if "engine" in slots else None

    @property
    def tmcc_id(self):
        return self._slots["tmcc_id"] if "tmcc_id" in self._slots else self.engine

    @property
    def dialog(self):
        slots = self._handler_input.request_envelope.request.intent.slots
        return get_canonical_slot(slots["dialog"]) if "dialog" in slots else None

    @property
    def duration(self) -> int | None:
        slots = self._handler_input.request_envelope.request.intent.slots
        duration_slot = slots["duration"] if "duration" in slots else None
        if duration_slot is not None and duration_slot.value:
            if duration_slot.value.startswith("PT"):
                duration = parse_duration(duration_slot.value).seconds
            else:
                raise UnsupportedDuration(duration_slot.value)
        else:
            duration = None
        return duration

    @property
    def speed(self):
        return get_canonical_slot(self._slots["speed"]) if "speed" in self._slots else None

    @property
    def coupler(self):
        return get_canonical_slot(self._slots["coupler"]) if "coupler" in self._slots else None

    @property
    def horn(self):
        return get_canonical_slot(self._slots["horn"]) if "horn" in self._slots else None

    @property
    def bell(self):
        return get_canonical_slot(self._slots["ring"]) if "ring" in self._slots else None

    @property
    def direction(self):
        return get_canonical_slot(self._slots["direction"]) if "direction" in self._slots else None

    @property
    def smoke(self):
        return get_canonical_slot(self._slots["smoke"]) if "smoke" in self._slots else None

    @property
    def on_off(self):
        return get_canonical_slot(self._slots["state"]) if "state" in self._slots else None

    @property
    def volume(self):
        return get_canonical_slot(self._slots["volume"]) if "volume" in self._slots else None


class SetPyTrainServerIntentHandler(PyTrainIntentHandler):
    def handle(self, handler_input: HandlerInput, raise_exception: bool = False) -> Response:
        super().handle(handler_input, raise_exception)
        state = get_state(handler_input)
        server = self._slots["server"].value if "server" in self._slots else None
        parts = server.split()
        new_parts = []
        http = ""
        for part in parts:
            part = part.lower().replace("://", "")
            if not part or part in ["colon", "slash", "", "://", ":", "/"]:
                continue
            if part == "dot":
                new_parts.append(".")
            elif part.startswith("http"):
                http = part
            else:
                new_parts.append(part)
        processed = "".join(new_parts)

        logger.info(f"Setting PyTrain URL Server: {server} Processed: {processed}")
        response = request_api_key(handler_input, state=state, server=processed)
        if response and response.status_code == 200:
            speak_output = f"Setting PyTrain server URL to {server}"
            reprompt = PYTRAIN_REPROMPT
            http = http if http else "http"
            url_base = f"{http}://{processed}/pytrain/v1"
            persist_state(handler_input, {"URL_BASE": url_base, "server": processed})
        else:
            speak_output = (
                f"There was a problem connecting to {processed}, please try again Error {response.status_code}"
            )
            reprompt = REQUEST_SERVER_REPROMPT
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
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        speed = self.speed
        dialog = self.dialog
        if engine is None:
            logger.warning(f"No {scope.title()} Number Specified")
            speak_output = f"I don't know what {scope} you want me to control, sorry!"
        else:
            opt = ""
            if dialog is not None:
                if dialog.value.id == "1":
                    opt = "?dialog=true"
                elif dialog.value.id == "2":
                    opt = "?immediate=true"
            speed_val = speed.value.id if speed else "0"
            url = f"{self.url_base}/{scope}/{engine.value}/speed_req/{speed_val}{opt}"
            speak_output = f"Changing the speed of {scope} {engine.value} to speed step {speed.value.name}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class BoostSpeedIntentHandler(PyTrainIntentHandler):
    """Handler for Boost Speed Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        duration = self.duration
        if engine is None:
            logger.warning("No Engine Specified")
            speak_output = "I don't know what engine you want me to boost, sorry!"
        else:
            dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
            dur_param = f"?duration={duration}" if duration else ""
            url = f"{self.url_base}/{scope}/{engine.value}/boost_req{dur_param}"
            speak_output = f"Boosting speed on {scope} {engine.value}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class BrakeSpeedIntentHandler(PyTrainIntentHandler):
    """Handler for Brake Speed Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        duration = self.duration
        if engine is None:
            logger.warning("No Engine Specified")
            speak_output = "I don't know what engine you want me to brake, sorry!"
        else:
            dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
            dur_param = f"?duration={duration}" if duration else ""
            url = f"{self.url_base}/{scope}/{engine.value}/brake_req{dur_param}"
            speak_output = f"Braking speed on {scope} {engine.value}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class OpenCouplerIntentHandler(PyTrainIntentHandler):
    """Handler for Open Coupler Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        coupler = self.coupler
        if engine is None:
            logger.warning("No {scope.title()} number specified")
            speak_output = "I don't know what {scope.title()} you want me to decouple, sorry!"
        else:
            if coupler and coupler.value.id == "1":
                url = f"{self.url_base}/{scope}/{engine.value}/rear_coupler_req"
                device = "rear"
            else:
                url = f"{self.url_base}/{scope}/{engine.value}/front_coupler_req"
                device = "front"
            speak_output = f"Opening {device} coupler on {scope} {engine.value}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class SoundHornIntentHandler(PyTrainIntentHandler):
    """Handler for Sound Horn Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        horn = self.horn
        duration = self.duration
        if engine is None:
            logger.warning(f"No {scope.title()} Specified")
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
            url = f"{self.url_base}/{scope}/{engine.value}/horn_req?option={opt}{dur_param}"
            speak_output = f"Sounding {device} on {scope} {engine.value}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class RingBellIntentHandler(PyTrainIntentHandler):
    """Handler for Ring Bell Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        bell = self.bell
        duration = self.duration
        if engine is None:
            logger.warning("No Engine Specified")
            speak_output = "I don't know what engine you want me to ring, sorry!"
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
            url = f"{self.url_base}/{scope}/{engine.value}/bell_req?option={opt}{dur_param}"
            speak_output = f"{device} on {scope} {engine.value}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class StartUpShutDownIntentHandler(PyTrainIntentHandler):
    """Handler for Start Up/Shut Down Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        on_off = self.on_off
        scope = self.scope
        engine = self.engine
        dialog = self.dialog
        if engine is None:
            logger.warning("No Engine/Train Number Specified")
            speak_output = f"I don't know what {scope} you want me to control, sorry!"
        elif on_off and on_off.value.id == "1":
            opt = "" if dialog is None or dialog.value.id == "0" else "?dialog=true"
            url = f"{self.url_base}/{scope}/{engine.value}/startup_req{opt}"
            speak_output = f"Starting up {scope} {engine.value}"
            response = self.post(url)
        else:
            opt = "" if dialog is None or dialog.value.id == "0" else "?dialog=true"
            url = f"{self.url_base}/{scope}/{engine.value}/shutdown_req{opt}"
            speak_output = f"Shutting down{scope} {engine.value}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class ShutDownIntentHandler(PyTrainIntentHandler):
    """Handler for Shut Down Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        dialog = self.dialog
        if engine is None:
            logger.warning("No Engine Number Specified")
            speak_output = f"I don't know what {scope} you want me to shut down, sorry!"
        else:
            opt = "" if dialog is None or dialog.value.id == "0" else "?dialog=true"
            url = f"{self.url_base}/{scope}/{engine.value}/shutdown_req{opt}"
            speak_output = f"Shutting down {scope} {engine.value}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class StopImmediateIntentHandler(PyTrainIntentHandler):
    """Handler for Stop Immediate Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        if engine is None:
            logger.warning("No {scope.title()} Number Specified")
            speak_output = "I don't know what {scope) you want me to stop, sorry!"
        else:
            url = f"{self.url_base}/{scope}/{engine.value}/stop_req"
            speak_output = f"<speak>Stopping {scope} {engine.value} "
            speak_output += "<voice name='Brian'><lang xml:lang='en-GB'>in it's tracks!</lang></voice></speak>"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class ResetIntentHandler(PyTrainIntentHandler):
    @property
    def url(self):
        return f"{self.url_base}/{self.scope}/{self.engine.value}/reset_req"

    @property
    def spoken_response(self):
        return f"Resetting {self.scope} {self.engine.value}"

    """Handler for Reset Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        if engine is None:
            logger.warning(f"No {scope.title()} Number Specified")
            speak_output = "I don't know what {scope} you want me to reset, sorry!"
        else:
            url = self.url
            speak_output = self.spoken_response
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class RefuelIntentHandler(ResetIntentHandler):
    @property
    def url(self):
        duration = self.duration if self.duration and self.duration >= 3 else 3
        return f"{self.url_base}/{self.scope}/{self.engine.value}/reset_req?hold=true&duration={duration}"

    @property
    def spoken_response(self):
        duration = self.duration
        dur = f" for {duration} second{'s' if duration and duration > 1 else ''}" if duration else ""
        return f"Refueling {self.scope} {self.engine.value}{dur}"


class SetDirectionIntentHandler(PyTrainIntentHandler):
    """Handler for Set Direction Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        dr = self.direction
        if engine is None:
            logger.warning("No {scope.title()} Number Specified")
            speak_output = "I don't know what {scope} to change the direction of, sorry!"
        else:
            if dr and dr.value.id == "1":
                url = f"{self.url_base}/{scope}/{engine.value}/reverse_req"
            elif dr and dr.value.id == "2":
                url = f"{self.url_base}/{scope}/{engine.value}/toggle_direction_req"
            else:
                url = f"{self.url_base}/{scope}/{engine.value}/forward_req"
            speak_output = f"Changing the direction of {scope} {engine.value} to {dr.value.name}"
            response = self.post(url)
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
    """Handler for Power District Intent."""

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
            speak_output = f"Turning {on_off.value.name} Accessory {tmcc_id.value}{dur}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class ChangeVolumeIntentHandler(PyTrainIntentHandler):
    """Handler for Change Volume Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        vol = self.volume
        if engine is None:
            logger.warning("No {scope.title()} Number Specified")
            speak_output = "I don't know what {scope} to change the volume of, sorry!"
        else:
            if vol and vol.value.id == "1":
                url = f"{self.url_base}/{scope}/{engine.value}/volume_down_req"
                directive = "Decreasing"
            else:
                url = f"{self.url_base}/{scope}/{engine.value}/volume_up_req"
                directive = "Increasing"
            speak_output = f"{directive} the volume of {scope} {engine.value}"
            response = self.post(url)
        return self.handle_response(response, handler_input, speak_output)


class SmokeLevelIntentHandler(PyTrainIntentHandler):
    """Handler for Smoke Level Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        scope = self.scope
        engine = self.engine
        smoke = self.smoke
        if engine is None:
            logger.warning("No {scope.title()} Number Specified")
            speak_output = f"I don't know what {scope} you want me to smoke, sorry!"
        else:
            opt = "?level=off" if smoke is None or smoke.value.id == "0" else f"?level={smoke.value.name.lower()}"
            url = f"{self.url_base}/{scope}/{engine.value}/smoke_level_req{opt}"
            speak_output = f"Setting smoke level on {scope} {engine.value} to {smoke.value.name}"
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
            speak_output = "I don't know the {scope} to query, sorry!"
        else:
            url = f"{self.url_base}/{scope}/{tmcc_id.value}"
            speak_output = f"Getting status of {scope} {tmcc_id.value}"
            response = self.get(url)
            if response and response.status_code == 200:
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
        return self.handle_response(response, handler_input, speak_output)


class FindTmccIdIntentHandler(PyTrainIntentHandler):
    """Handler for Find TMCC ID Intent."""

    def handle(self, handler_input, raise_exception: bool = True) -> Response:
        super().handle(handler_input)
        response = None
        engine_num = self.engine
        if engine_num is None:
            logger.warning("No Engine Number Specified")
            speak_output = "I don't know the engine number to query, sorry!"
        else:
            engine_num = engine_num.value
            speak_output = ""
            url = f"{self.url_base}/engine/{engine_num}"
            response = self.get(url)

            if response and response.status_code == 200:
                # Handle the response data
                data = response.json()
                tmcc_id = data.get("tmcc_id", None)
                if tmcc_id:
                    speak_output = "<speak>The TMCC <say-as interpret-as='spell-out'>ID</say-as> "
                    speak_output += f"of Engine number {engine_num} is {tmcc_id}</speak>"
                else:
                    speak_output = f"I couldn't find any engine numbered {engine_num}, sorry!"
        return self.handle_response(response, handler_input, speak_output)


class HelpIntentHandler(AbstractRequestHandler):
    """Handler for Help Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = """
            Control your Lionel layout by voice!. Here are just a few examples of what can say:

            'Power up engine 67',
            'Set the speed of engine 23 to slow',
            'Blow the whistle on Engine 5 for 30 seconds',
            "Reverse Engine sixty three',
            'Reset engine five',
            'Refuel train seventeen for 10 seconds',
            'Shut down train 33',
            'throw switch 5 to thru'
            'fire route 10'
            'Get status of engine 23',

            In cace of trouble, say: 'Emergency Halt',

            What would you like to do?
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


class StopIntentHandler(AbstractRequestHandler):
    """Handler for Stop Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.StopIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "Goodbye from PyTrain!"

        return handler_input.response_builder.speak(speak_output).set_should_end_session(True).response


class SessionEndedRequestHandler(AbstractRequestHandler):
    """Handler for Session End."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

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
    """Generic error handling to capture any syntax or routing errors. If you receive an error
    stating the request handler chain is not found, you have not implemented a handler for
    the intent being invoked or included it in the skill builder below.
    """

    def can_handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> bool
        return True

    def handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> Response
        logger.error(exception, exc_info=True)

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
        else:
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
sb.add_request_handler(SetPyTrainServerIntentHandler())
sb.add_request_handler(HaltIntentHandler())
sb.add_request_handler(StartUpShutDownIntentHandler())
sb.add_request_handler(SoundHornIntentHandler())
sb.add_request_handler(SpeedIntentHandler())
sb.add_request_handler(StopImmediateIntentHandler())
sb.add_request_handler(RingBellIntentHandler())
sb.add_request_handler(ResetIntentHandler())
sb.add_request_handler(RefuelIntentHandler())
sb.add_request_handler(SetDirectionIntentHandler())
sb.add_request_handler(OpenCouplerIntentHandler())
sb.add_request_handler(SmokeLevelIntentHandler())
sb.add_request_handler(ChangeVolumeIntentHandler())
sb.add_request_handler(ThrowSwitchIntentHandler())
sb.add_request_handler(FireRouteIntentHandler())
sb.add_request_handler(PowerDistrictIntentHandler())
sb.add_request_handler(AccessoryIntentHandler())
sb.add_request_handler(FindTmccIdIntentHandler())
sb.add_request_handler(GetStatusIntentHandler())
sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelIntentHandler())
sb.add_request_handler(StopIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())
sb.add_request_handler(
    IntentReflectorHandler()
)  # make sure IntentReflectorHandler is last so it doesn't override your custom intent handlers

sb.add_exception_handler(CatchAllExceptionHandler())

handler = sb.lambda_handler()
