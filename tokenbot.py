# token - A maubot plugin to manage MAS user registration tokens
# Copyright (C) 2022 Michael Auer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper
from maubot import Plugin, MessageEvent
from maubot.handlers import command

import asyncio
import base64
import json
import datetime
import time
from typing import Any, Dict, List, Optional, Tuple, Type
from urllib.parse import urljoin

error_msg_no_auth = "My mom said I'm not allowed to talk to strangers."
token_msg = """
**{token}** (ID: {token_id})\n
- valid: {valid}\n
- usage_limit: {usage_limit}\n
- times_used: {times_used}\n
- expires_at: {expires_at}\n
- revoked_at: {revoked_at}\n
- last_used_at: {last_used_at}\n
- created_at: {created_at}\n
"""


class Config(BaseProxyConfig):

    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("base_command")
        helper.copy("whitelist")
        helper.copy("room_whitelist")
        helper.copy("admin_api")
        helper.copy("token_url")
        helper.copy("client_id")
        helper.copy("client_secret")
        helper.copy("token_scope")
        helper.copy("default_uses_allowed")
        helper.copy("default_expiry_time")


def _format_datetime(value: Optional[str]) -> str:
    if not value:
        return "never"
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _format_token(resource: Dict[str, Any]) -> str:
    attributes = resource.get("attributes", {})
    usage_limit = attributes.get("usage_limit")
    last_used_at = attributes.get("last_used_at")
    revoked_at = attributes.get("revoked_at")
    return token_msg.format(
        token=attributes.get("token", "<unknown>"),
        token_id=resource.get("id", "<unknown>"),
        valid=attributes.get("valid"),
        usage_limit=usage_limit if usage_limit is not None else "unlimited",
        times_used=attributes.get("times_used"),
        expires_at=_format_datetime(attributes.get("expires_at")),
        revoked_at=_format_datetime(revoked_at),
        last_used_at=_format_datetime(last_used_at),
        created_at=_format_datetime(attributes.get("created_at")))


def parse_single_token(resource: Dict[str, Any]) -> str:
    if "data" in resource:
        resource = resource["data"]
    return _format_token(resource)


def parse_tokens(payload: Dict[str, Any]) -> str:
    data = payload.get("data") or []
    if not data:
        return "No registration tokens found."
    valid_tokens = "\u2705 Valid Tokens \u2705\n"
    invalid_tokens = "\u274C Invalid Tokens \u274C\n"
    valid_found = False
    invalid_found = False
    for resource in data:
        attributes = resource.get("attributes", {})
        entry = "- {} (ID: {})\n".format(attributes.get("token",
                                                        "<unknown>"),
                                         resource.get("id", "<unknown>"))
        if attributes.get("valid"):
            valid_tokens += entry
            valid_found = True
        else:
            invalid_tokens += entry
            invalid_found = True
    if not invalid_found:
        invalid_tokens += "- (none)\n"
    if not valid_found:
        valid_tokens += "- (none)\n"
    return invalid_tokens + "\n" + valid_tokens


def _format_error_message(error: Any) -> str:
    if isinstance(error, dict):
        status = error.get("status")
        message = error.get("message") or "Unknown error"
        if status:
            return f"ERROR {status}: {message}"
        return message
    return str(error)


class TokenBot(Plugin):

    def authenticate(self, event: MessageEvent) -> bool:
        user_whitelist = set(self.config.get("whitelist", []))
        room_whitelist = set(self.config.get("room_whitelist", []))
        if event.sender in user_whitelist:
            return True
        room_id = getattr(event, "room_id", None)
        if room_id and room_id in room_whitelist:
            return True
        return False

    @classmethod
    def get_config_class(cls) -> Type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        self.config.load_and_update()
        self._access_token: Optional[str] = None
        self._access_token_expiry: float = 0.0
        self._token_lock = asyncio.Lock()

    def _build_token_auth_header(self) -> str:
        creds = "{}:{}".format(self.config["client_id"],
                               self.config["client_secret"]).encode("utf-8")
        encoded = base64.b64encode(creds).decode("ascii")
        return f"Basic {encoded}"

    async def _fetch_access_token(self) -> Tuple[bool, Any]:
        headers = {
            "Authorization": self._build_token_auth_header(),
            "content-type": "application/x-www-form-urlencoded",
        }
        body = "grant_type=client_credentials&scope={}".format(
            self.config["token_scope"])
        response = await self.http.post(self.config["token_url"],
                                        data=body,
                                        headers=headers)
        if response.status >= 400:
            try:
                payload = await response.json()
                message = payload.get("error_description") or payload.get(
                    "error") or ""
            except Exception:
                message = await response.text()
            return False, {
                "status": response.status,
                "message":
                message or "Failed to obtain MAS access token."
            }
        data = await response.json()
        token = data.get("access_token")
        expires_in = data.get("expires_in", 300)
        if not token:
            return False, {
                "status":
                response.status,
                "message":
                "MAS token response did not include access_token."
            }
        # Cache with a small safety margin.
        self._access_token = token
        self._access_token_expiry = time.time() + max(int(expires_in) - 30, 0)
        return True, token

    async def _get_access_token(self) -> Tuple[bool, Any]:
        async with self._token_lock:
            if (self._access_token
                    and time.time() < self._access_token_expiry):
                return True, self._access_token
            self._access_token = None
            self._access_token_expiry = 0.0
            return await self._fetch_access_token()

    def _invalidate_cached_token(self) -> None:
        self._access_token = None
        self._access_token_expiry = 0.0

    async def _mas_request(self,
                           method: str,
                           base_url: str,
                           path: str,
                           body: Optional[Dict[str, Any]] = None,
                           params: Optional[Dict[str, Any]] = None,
                           allow_retry: bool = True) -> Tuple[bool, Any]:
        token_ok, token_or_error = await self._get_access_token()
        if not token_ok:
            return False, token_or_error
        access_token: str = token_or_error
        if not path.startswith("http"):
            if not path.startswith("/"):
                path = "/" + path
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        else:
            url = path
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        request = getattr(self.http, method.lower())
        data = json.dumps(body) if body is not None else None
        response = await request(url, headers=headers, params=params, data=data)
        if response.status == 204:
            return True, None
        if response.status >= 400:
            if response.status == 401 and allow_retry:
                # Token likely expired earlier than expected; refresh and retry once.
                self._invalidate_cached_token()
                retry_ok, _ = await self._get_access_token()
                if retry_ok:
                    return await self._mas_request(method,
                                                   base_url,
                                                   path,
                                                   body=body,
                                                   params=params,
                                                   allow_retry=False)
            try:
                error_payload = await response.json()
                if isinstance(error_payload, dict) and "errors" in error_payload:
                    message = ", ".join(
                        err.get("title", "") for err in error_payload["errors"])
                else:
                    message = json.dumps(error_payload)
            except Exception:
                message = await response.text()
            return False, {
                "status": response.status,
                "message": message or "Unexpected error"
            }
        try:
            return True, await response.json()
        except Exception:
            text = await response.text()
            return False, {
                "status": response.status,
                "message": text or "Failed to decode JSON response"
            }

    async def _collect_tokens(self, base_url: str) -> Tuple[bool, Any]:
        tokens: List[Dict[str, Any]] = []
        path: Optional[str] = "/v1/user-registration-tokens"
        params: Optional[Dict[str, Any]] = {"page[first]": 100}
        while path:
            ret, payload = await self._mas_request("get",
                                                   base_url,
                                                   path,
                                                   params=params)
            if not ret:
                return False, payload
            page_tokens = payload.get("data") or []
            tokens.extend(page_tokens)
            links = payload.get("links") or {}
            next_path = links.get("next")
            if next_path:
                path = next_path
                params = None
            else:
                path = None
        return True, tokens

    async def _get_token(self, base_url: str,
                         identifier: Optional[str]):
        if identifier:
            # First try by ID.
            ret, payload = await self._mas_request(
                "get", base_url, f"/v1/user-registration-tokens/{identifier}")
            if ret:
                return True, payload.get("data")
            if payload.get("status") != 404:
                return False, payload
            # Fallback to search by token string.
        ret, tokens_or_error = await self._collect_tokens(base_url)
        if not ret:
            return False, tokens_or_error
        if not identifier:
            return True, {"data": tokens_or_error}
        for resource in tokens_or_error:
            attributes = resource.get("attributes", {})
            if attributes.get("token") == identifier:
                return True, resource
        return False, {
            "status": 404,
            "message": f"Registration token '{identifier}' not found."
        }

    async def _gen_token(self, base_url: str,
                         uses_allowed: Optional[int],
                         expiry_seconds: Optional[int]):
        payload: Dict[str, Any] = {}
        if uses_allowed is not None and uses_allowed >= 0:
            payload["usage_limit"] = uses_allowed
        if expiry_seconds is not None and expiry_seconds >= 0:
            expires_at = (datetime.datetime.now(datetime.timezone.utc) +
                          datetime.timedelta(seconds=expiry_seconds))
            payload["expires_at"] = expires_at.replace(
                microsecond=0).isoformat().replace("+00:00", "Z")
        ret, response = await self._mas_request(
            "post", base_url,
            "/v1/user-registration-tokens", body=payload)
        if not ret:
            return False, response
        return True, response.get("data")

    async def _revoke_token(self, base_url: str,
                            resource_id: str):
        return await self._mas_request(
            "post", base_url,
            f"/v1/user-registration-tokens/{resource_id}/revoke")

    async def _unrevoke_token(self, base_url: str,
                              resource_id: str):
        return await self._mas_request(
            "post", base_url,
            f"/v1/user-registration-tokens/{resource_id}/unrevoke")

    @command.new(name=lambda self: self.config["base_command"],
                 help="List available Tokens",
                 require_subcommand=True)
    async def token(self, event: MessageEvent) -> None:
        pass

    @token.subcommand(name="list", help="List all [or specific] Tokens")
    @command.argument("token", required=False, pass_raw=True)
    async def list_tokens(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event):
            await event.reply(error_msg_no_auth)
            return
        identifier = token.strip() if token else None
        ret, available_token = await self._get_token(
            self.config["admin_api"], identifier)
        if not ret:
            await event.reply(_format_error_message(available_token))
            return
        if identifier:
            await event.reply(parse_single_token(available_token))
        else:
            await event.reply(parse_tokens(available_token))

    @token.subcommand(name="generate", help="Generate a Token")
    @command.argument("uses",
                      parser=lambda val: int(val) if val else None,
                      required=False)
    @command.argument("expiry",
                      parser=lambda val: int(val) if val else None,
                      required=False)
    async def generate_token(self, event: MessageEvent, uses: int,
                             expiry: int) -> None:
        if not self.authenticate(event):
            await event.reply(error_msg_no_auth)
            return
        if uses is None:
            uses = self.config["default_uses_allowed"]
        if expiry is None:
            expiry = self.config["default_expiry_time"]
        ret, available_token = await self._gen_token(
            self.config["admin_api"], uses, expiry)
        msg = ""
        if ret:
            msg = parse_single_token(available_token)
        else:
            msg = _format_error_message(available_token)
        await event.reply(msg)

    @token.subcommand(name="delete", help="Delete a Token")
    @command.argument("token", required=True, pass_raw=True)
    async def delete_token(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event):
            await event.reply(error_msg_no_auth)
            return
        identifier = token.strip()
        ret, token_resource = await self._get_token(
            self.config["admin_api"], identifier)
        if not ret:
            await event.reply(_format_error_message(token_resource))
            return
        resource_id = token_resource.get("id")
        if not resource_id:
            await event.reply(
                f"Unable to determine resource ID for token '{identifier}'.")
            return
        ret, response = await self._revoke_token(
            self.config["admin_api"], resource_id)
        if ret:
            await event.reply("Token revoked!\n" + parse_single_token(response))
        else:
            await event.reply(_format_error_message(response))

    @token.subcommand(name="unrevoke",
                      help="Unrevoke a previously revoked Token")
    @command.argument("token", required=True, pass_raw=True)
    async def unrevoke_token(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event):
            await event.reply(error_msg_no_auth)
            return
        identifier = token.strip()
        ret, token_resource = await self._get_token(
            self.config["admin_api"], identifier)
        if not ret:
            await event.reply(_format_error_message(token_resource))
            return
        resource_id = token_resource.get("id")
        if not resource_id:
            await event.reply(
                f"Unable to determine resource ID for token '{identifier}'.")
            return
        ret, response = await self._unrevoke_token(
            self.config["admin_api"], resource_id)
        if ret:
            await event.reply("Token unrevoked!\n" +
                              parse_single_token(response))
        else:
            await event.reply(_format_error_message(response))
