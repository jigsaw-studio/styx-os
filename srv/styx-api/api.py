# Copyright (c) 2024-2025 Steve Castellotti
# This file is part of styx-os and is released under the MIT License.
# See LICENSE file in the project root for full license information.

import argparse
import datetime
import dateutil.relativedelta, dateutil.tz
import ipaddress
import os
import sqlite3
import uvicorn
from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel
from typing import Optional

# Second-level labels that make a three-label registrable name (bbc.co.uk).
SECOND_LEVEL_LABELS = ('co', 'com', 'net', 'org', 'gov', 'ac', 'edu')


def block_of(host: str) -> str:
    """The city block a host belongs to (see the contract's block rule)."""
    host = host.lower()
    if host.endswith('.'):
        host = host[:-1]
    parts = host.split('.')
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"{parts[0]}.{parts[1]}.0.0/16"
    if ':' in host:
        return host
    if len(parts) == 1:
        return host
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL_LABELS:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def scope_of(remote: Optional[str]) -> str:
    """'lan' for a private or link-local IPv4/IPv6 literal, else 'wan'."""
    try:
        address = ipaddress.ip_address(remote)
    except ValueError:
        return 'wan'
    return 'lan' if address.is_private or address.is_link_local else 'wan'


def seconds_ago(timestamp: Optional[str], now: datetime.datetime) -> int:
    """Whole seconds from a 'YYYY-MM-DD HH:MM:SS' UTC timestamp to now, never below 0."""
    if not timestamp:
        return 0
    then = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return max(0, int((now - then).total_seconds()))


def epoch_of(timestamp: str) -> int:
    """A 'YYYY-MM-DD HH:MM:SS' UTC timestamp as epoch seconds."""
    return int(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp())


def split_list(value: Optional[str], limit: int, numeric: bool = False) -> list:
    """A GROUP_CONCAT result ('443,80') as a sorted list without duplicates, cut to limit."""
    if not value:
        return []
    items = set()
    for piece in str(value).split(','):
        piece = piece.strip()
        if not piece:
            continue
        if numeric:
            try:
                items.add(int(piece))
            except ValueError:
                continue
        else:
            items.add(piece)
    return sorted(items)[:limit]


class TrafficAPI:
    def __init__(self, database_path: str):
        self.app = FastAPI()
        self.database_path = database_path
        self.setup_routes()

    class TrafficTotals(BaseModel):
        sent: int = 0
        received: int = 0

    class TrafficSummary(BaseModel):
        address: str
        sent: int = 0
        received: int = 0

    class TrafficRawData(BaseModel):
        timestamp: str
        local: str
        remote: str
        port: int
        sent: int
        received: int
        domain: Optional[str]

    class TrafficMatrixSummary(BaseModel):
        address: str
        sent: int = 0
        received: int = 0
        count: int = 0

    class HostSummary(BaseModel):
        host: str
        block: str
        ports: list[int] = []
        sent: int = 0
        received: int = 0
        count: int = 1
        open: int = 0
        blocked: int = 0
        untunnelled: bool = False
        scope: str = ""
        first_seen_ago: int = 0
        last_seen_ago: int = 0
        clients: list[str] = []
        tools: list[str] = []
        services: list[str] = []

    class LinkSummary(BaseModel):
        source: str
        source_kind: str
        via: str = ""
        target: str
        sent: int = 0
        received: int = 0
        count: int = 1
        open: int = 0
        blocked: int = 0
        last_seen_ago: int = 0

    class FlowRow(BaseModel):
        host: str
        time: int
        ago: int = 0
        source: str
        via: str = ""
        tool: Optional[str] = None
        port: Optional[int] = None
        proto: Optional[str] = None
        sent: int = 0
        received: int = 0
        state: str = "finished"
        blocked: bool = False
        rule: Optional[str] = None
        method: Optional[str] = None
        url: Optional[str] = None
        label: Optional[str] = None

    def query_database(self, query: str, params: tuple):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchall()
        conn.close()
        return result

    @staticmethod
    def construct_timestamp(
            date_part: Optional[str],
            time_part: Optional[str],
            is_start: bool,
            relative: Optional[str] = None,
            timezone: Optional[str] = None
    ):
        utc_now = datetime.datetime.now(datetime.timezone.utc)

        if timezone:
            try:
                # Handle timezone abbreviations and full names
                tz = dateutil.tz.gettz(timezone)
                if tz is None:
                    raise HTTPException(status_code=400, detail="Invalid timezone")
                utc_now = utc_now.astimezone(tz)
            except Exception as http_e:
                raise HTTPException(status_code=400, detail=f"Timezone error: {str(http_e)}")
        else:
            tz = dateutil.tz.UTC  # Default to UTC if no timezone is provided

        if relative:
            try:
                time_amount = int(relative[:-1])
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid relative time")
            unit = relative[-1]

            if unit == 's':
                delta = datetime.timedelta(seconds=time_amount)
            elif unit == 'm':
                delta = datetime.timedelta(minutes=time_amount)
            elif unit == 'h':
                delta = datetime.timedelta(hours=time_amount)
            elif unit == 'd':
                delta = datetime.timedelta(days=time_amount)
            elif unit == 'y':
                delta = dateutil.relativedelta.relativedelta(years=time_amount)
            else:
                raise HTTPException(status_code=400, detail="Invalid relative time unit")

            if is_start:
                utc_time = (utc_now - delta)
            else:
                utc_time = utc_now

            return utc_time.strftime("%Y-%m-%d %H:%M:%S")

        if date_part and time_part:
            local_time = datetime.datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
            local_time = local_time.replace(tzinfo=tz)
            utc_time = local_time.astimezone(dateutil.tz.UTC)
            return utc_time.strftime("%Y-%m-%d %H:%M:%S")
        elif date_part:
            time_part = "00:00:00" if is_start else "23:59:59"
            local_time = datetime.datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
            local_time = local_time.replace(tzinfo=tz)
            utc_time = local_time.astimezone(dateutil.tz.UTC)
            return utc_time.strftime("%Y-%m-%d %H:%M:%S")
        elif time_part:
            today = utc_now.date().strftime("%Y-%m-%d")
            local_time = datetime.datetime.strptime(f"{today} {time_part}", "%Y-%m-%d %H:%M:%S")
            local_time = local_time.replace(tzinfo=tz)
            utc_time = local_time.astimezone(dateutil.tz.UTC)
            return utc_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return None

    def setup_routes(self):
        @self.app.get(
            "/v1/domain",
            response_model=list[self.TrafficSummary],
            summary="Retrieve traffic summary by domain",
            description="""
Retrieves a summary of network traffic grouped by domain name.
Each entry includes:

- **Address:** The domain name accessed.
- **Sent:** Total bytes sent to this domain.
- **Received:** Total bytes received from this domain.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.
            """
        )
        def get_domain_summary(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT domain, SUM(sent) as sent, SUM(received) as received
                FROM traffic
                WHERE domain IS NOT NULL
            '''
            params = []

            start_timestamp = self.construct_timestamp(
                start_date, start_time, is_start=True, relative=relative, timezone=timezone
            )
            end_timestamp = self.construct_timestamp(
                end_date, end_time, is_start=False, relative=None, timezone=timezone
            )

            if start_timestamp:
                query += " AND timestamp >= ?"
                params.append(start_timestamp)

            if end_timestamp:
                query += " AND timestamp <= ?"
                params.append(end_timestamp)

            if client:
                query += " AND local = ?"
                params.append(client)

            query += " GROUP BY domain"

            results = self.query_database(query, tuple(params))

            return [self.TrafficSummary(address=row[0], sent=row[1] or 0, received=row[2] or 0) for row in results]

        @self.app.get(
            "/v1/ip",
            response_model=list[self.TrafficSummary],
            summary="Retrieve traffic summary by remote IP",
            description="""
Retrieves a summary of network traffic grouped by remote IP address.
Each entry includes:

- **Address:** The remote IP address accessed.
- **Sent:** Total bytes sent to this IP.
- **Received:** Total bytes received from this IP.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.
            """
        )
        def get_ip_summary(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT remote, SUM(sent) as sent, SUM(received) as received
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            query += " GROUP BY remote"

            results = self.query_database(query, tuple(params))

            return [self.TrafficSummary(address=row[0], sent=row[1] or 0, received=row[2] or 0) for row in results]

        @self.app.get(
            "/v1/local",
            response_model=list[self.TrafficSummary],
            summary="Retrieve traffic summary by local IP",
            description="""
Retrieves a summary of network traffic grouped by local IP addresses.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.
            """
        )
        def get_local_summary(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT local, SUM(sent) as sent, SUM(received) as received
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, None)

            query += " GROUP BY local"

            results = self.query_database(query, tuple(params))

            return [self.TrafficSummary(address=row[0], sent=row[1] or 0, received=row[2] or 0) for row in results]

        @self.app.get(
            "/v1/network",
            response_model=self.TrafficTotals,
            summary="Retrieve total network traffic",
            description="""
Retrieves the total amount of network traffic sent and received.

**Response:**
```json
{
  "sent": 1048576,
  "received": 2097152
}
```

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.
            """
        )
        def get_network_summary(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT SUM(sent) as sent, SUM(received) as received
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            results = self.query_database(query, tuple(params))

            if results and results[0][0] is not None and results[0][1] is not None:
                return self.TrafficTotals(sent=results[0][0] or 0, received=results[0][1] or 0)
            else:
                return self.TrafficTotals(sent=0, received=0)

        @self.app.get(
            "/v1/matrix",
            response_model=list[self.TrafficMatrixSummary],
            summary="Retrieve sorted traffic summary by domain or IP",
            description="""
Retrieves a sorted summary of network traffic grouped by domain name (if available) or remote IP address. 
Each entry includes:

- **Address:** The domain name if known, otherwise the remote IP (optionally with port).
- **Sent:** Total bytes sent to this address.
- **Received:** Total bytes received from this address.
- **Count:** The number of times this address was accessed.

Results are ordered by **highest access count**.

**Query Parameters:**
- `start_date`: Start date filter (`YYYY-MM-DD`).
- `start_time`: Start time filter (`HH:MM:SS`).
- `end_date`: End date filter (`YYYY-MM-DD`).
- `end_time`: End time filter (`HH:MM:SS`).
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps (e.g., `UTC`, `America/New_York`).
- `client`: Filter by a specific local IP.

**Example Response:**
```json
[
  {
    "address": "example.com:443",
    "sent": 12345,
    "received": 67890,
    "count": 42
  },
  {
    "address": "192.168.1.100:80",
    "sent": 5120,
    "received": 10240,
    "count": 18
  }
]
```
    """
        )
        def get_matrix_summary(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT COALESCE(domain, remote) as address, port, 
                       SUM(sent) as sent, SUM(received) as received, COUNT(*) as count
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            query += " GROUP BY address, port ORDER BY count DESC"

            results = self.query_database(query, tuple(params))

            return [
                self.TrafficMatrixSummary(
                    address=f"{row[0]}:{row[1]}" if row[1] else row[0],
                    sent=row[2] or 0,
                    received=row[3] or 0,
                    count=row[4] or 0
                ) for row in results
            ]

        @self.app.get(
            "/v1/remote",
            response_model=list[self.TrafficSummary],
            summary="Retrieve traffic summary by remote address with port",
            description="""
Retrieves a summary of network traffic grouped by **remote domain or IP**, including **port information**.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.
            """
        )
        def get_remote_summary(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT 
                    COALESCE(domain, remote) as address, 
                    port, 
                    SUM(sent) as sent, 
                    SUM(received) as received
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            query += " GROUP BY address, port"

            results = self.query_database(query, tuple(params))

            return [
                self.TrafficSummary(
                    address=f"{row[0]}:{row[1]}", sent=row[2] or 0, received=row[3] or 0
                ) for row in results
            ]

        @self.app.get(
            "/v1/raw",
            response_model=list[self.TrafficRawData],
            summary="Retrieve raw network traffic logs",
            description="""
Retrieves raw network traffic logs, including timestamps and data transferred.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.

**Example Response:**
```json
[
  {
    "timestamp": "2024-10-13 12:34:56",
    "local": "192.168.1.10",
    "remote": "93.184.216.34",
    "port": 443,
    "sent": 1500,
    "received": 3000,
    "domain": "example.com"
  }
]
```
            """
        )
        def get_raw_data(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT timestamp, local, remote, port, sent, received, domain
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            results = self.query_database(query, tuple(params))

            # Convert timestamps back to the requested timezone if provided
            if timezone:
                tz = dateutil.tz.gettz(timezone)
                if tz is None:
                    raise HTTPException(status_code=400, detail="Invalid timezone")
            else:
                tz = dateutil.tz.UTC  # Default to UTC if no timezone is provided

            return [
                self.TrafficRawData(
                    timestamp=datetime.datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dateutil.tz.UTC).astimezone(tz).strftime("%Y-%m-%d %H:%M:%S"),
                    local=row[1],
                    remote=row[2],
                    port=row[3],
                    sent=row[4] or 0,
                    received=row[5] or 0,
                    domain=row[6]
                ) for row in results
            ]

        @self.app.get(
            "/v1/hosts",
            response_model=list[self.HostSummary],
            summary="Retrieve the remote hosts reached (one row per host)",
            description="""
Retrieves one row per remote host, ports merged, for a city of towers: the more
traffic, the bigger the tower. Hosts of one registrable domain share a **block**.
Results are ordered by **highest count**, then host name, and cut at 256 rows.

Each entry includes:

- **Host:** The domain name if known, otherwise the remote IP, in lower case.
- **Block:** The city block (`example.org` for `www.example.org`, `a.b.0.0/16` for an IPv4 literal).
- **Ports:** The distinct ports reached, ascending, at most 16.
- **Sent / Received:** Total bytes up / down.
- **Count:** How many records (seconds with traffic) there are for this host.
- **Scope:** `lan` for a private or link-local address, else `wan`.
- **First seen ago / Last seen ago:** Whole seconds from the first and the latest
  record in the window to now.
- **Clients:** The local devices that reached it, at most 8.

Always `0`, `false` or empty on the Pi: `open`, `blocked` (Pi-hole's refused queries
are not captured), `untunnelled`, `tools`, `services`. Another source of the same
contract, Layman, fills them.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.

**Example Response:**
```json
[
  {
    "host": "www.example.org",
    "block": "example.org",
    "ports": [80, 443],
    "sent": 5120,
    "received": 88211,
    "count": 14,
    "open": 0,
    "blocked": 0,
    "untunnelled": false,
    "scope": "wan",
    "first_seen_ago": 840,
    "last_seen_ago": 3,
    "clients": ["172.16.100.20"],
    "tools": [],
    "services": []
  }
]
```
            """
        )
        def get_hosts(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT LOWER(COALESCE(domain, remote)) AS host,
                       SUM(sent), SUM(received), COUNT(*),
                       MIN(timestamp), MAX(timestamp),
                       GROUP_CONCAT(DISTINCT port), GROUP_CONCAT(DISTINCT local), MIN(remote)
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            query += " GROUP BY host ORDER BY COUNT(*) DESC, host ASC LIMIT 256"

            results = self.query_database(query, tuple(params))
            now = datetime.datetime.now(datetime.timezone.utc)

            return [
                self.HostSummary(
                    host=row[0],
                    block=block_of(row[0]),
                    ports=split_list(row[6], 16, numeric=True),
                    sent=row[1] or 0,
                    received=row[2] or 0,
                    count=row[3] or 1,
                    scope=scope_of(row[8]),
                    first_seen_ago=seconds_ago(row[4], now),
                    last_seen_ago=seconds_ago(row[5], now),
                    clients=split_list(row[7], 8)
                ) for row in results if row[0]
            ]

        @self.app.get(
            "/v1/links",
            response_model=list[self.LinkSummary],
            summary="Retrieve who talks to whom (one row per device and host)",
            description="""
Retrieves one row per (local device, remote host): the traffic between a device
and a tower. Results are ordered by **highest count**, then device, then host, and
cut at 512 rows.

Each entry includes:

- **Source:** The local device's IP. **Source kind:** always `device` on the Pi.
- **Via:** Always empty on the Pi (another source, Layman, names the gate or tool).
- **Target:** A host, as in `/v1/hosts`.
- **Sent / Received / Count / Last seen ago:** As in `/v1/hosts`, for this pair.

Always `0` on the Pi: `open`, `blocked`.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.

**Example Response:**
```json
[
  {
    "source": "172.16.100.20",
    "source_kind": "device",
    "via": "",
    "target": "www.example.org",
    "sent": 5120,
    "received": 88211,
    "count": 14,
    "open": 0,
    "blocked": 0,
    "last_seen_ago": 3
  }
]
```
            """
        )
        def get_links(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            query = '''
                SELECT local, LOWER(COALESCE(domain, remote)) AS host,
                       SUM(sent), SUM(received), COUNT(*), MAX(timestamp)
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            query += " GROUP BY local, host ORDER BY COUNT(*) DESC, local ASC, host ASC LIMIT 512"

            results = self.query_database(query, tuple(params))
            now = datetime.datetime.now(datetime.timezone.utc)

            return [
                self.LinkSummary(
                    source=row[0],
                    source_kind="device",
                    via="",
                    target=row[1],
                    sent=row[2] or 0,
                    received=row[3] or 0,
                    count=row[4] or 1,
                    last_seen_ago=seconds_ago(row[5], now)
                ) for row in results if row[0] and row[1]
            ]

        @self.app.get(
            "/v1/flows",
            response_model=list[self.FlowRow],
            summary="Retrieve the newest activity, optionally for one host",
            description="""
Retrieves the log, newest first: what a tower's menu lists. On the Pi one row is
**one second of traffic** between one device and one host, so a busy connection is
many rows.

Each entry includes:

- **Host:** As in `/v1/hosts`. **Port:** The port reached.
- **Time / Ago:** The row's time (epoch seconds, UTC) and the seconds from it to now.
- **Source:** The local device's IP. **Via:** Always empty on the Pi.
- **Sent / Received:** The row's bytes. **State:** Always `finished` on the Pi.

Always `null`, `false` or empty on the Pi: `tool`, `proto`, `blocked`, `rule`,
`method`, `url`, `label`. Another source of the same contract, Layman, fills them.

**Query Parameters:**
- `start_date`, `start_time`, `end_date`, `end_time`: Absolute time filters.
- `relative`: Relative time range (e.g., `60s`, `30m`, `1h`).
- `timezone`: Timezone for timestamps.
- `client`: Filter by a specific local IP.
- `host`: Only this host (case-insensitive, no port).
- `limit`: How many rows, 1 to 500 (default 100). Anything else answers 400.

**Example Response:**
```json
[
  {
    "host": "www.example.org",
    "time": 1794856060,
    "ago": 3,
    "source": "172.16.100.20",
    "via": "",
    "tool": null,
    "port": 443,
    "proto": null,
    "sent": 39,
    "received": 177,
    "state": "finished",
    "blocked": false,
    "rule": null,
    "method": null,
    "url": null,
    "label": null
  }
]
```
            """
        )
        def get_flows(
                start_date: Optional[str] = Query(None),
                start_time: Optional[str] = Query(None),
                end_date: Optional[str] = Query(None),
                end_time: Optional[str] = Query(None),
                relative: Optional[str] = Query(None),
                timezone: Optional[str] = Query(None),
                client: Optional[str] = Query(None),
                host: Optional[str] = Query(None),
                limit: Optional[str] = Query(None)
        ):
            if relative and (start_date or start_time or end_date or end_time or timezone):
                raise HTTPException(status_code=400, detail="Cannot specify both relative time and absolute time parameters")

            row_limit = 100
            if limit is not None:
                try:
                    row_limit = int(limit)
                except ValueError:
                    row_limit = 0
                if not 1 <= row_limit <= 500:
                    raise HTTPException(status_code=400, detail="limit must be an integer from 1 to 500")

            query = '''
                SELECT timestamp, local, LOWER(COALESCE(domain, remote)) AS host, port, sent, received
                FROM traffic
            '''
            (query, params) = self.process_query_parameters(query, start_date, start_time, end_date, end_time, timezone, relative, client)

            if host:
                query = self.add_condition(query, params, "LOWER(COALESCE(domain, remote)) = ?", host.lower())

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(row_limit)

            results = self.query_database(query, tuple(params))
            now = datetime.datetime.now(datetime.timezone.utc)

            return [
                self.FlowRow(
                    host=row[2],
                    time=epoch_of(row[0]),
                    ago=seconds_ago(row[0], now),
                    source=row[1],
                    port=row[3],
                    sent=row[4] or 0,
                    received=row[5] or 0
                ) for row in results if row[2] and row[1]
            ]

    def process_query_parameters(self, query, start_date, start_time, end_date, end_time, timezone, relative, client):
        params = []

        start_timestamp = self.construct_timestamp(
            start_date, start_time, is_start=True, relative=relative, timezone=timezone
        )
        end_timestamp = self.construct_timestamp(
            end_date, end_time, is_start=False, relative=None, timezone=timezone
        )

        first_conditional = True

        if start_timestamp:
            first_conditional = False
            query += " WHERE timestamp >= ?"
            params.append(start_timestamp)

        if end_timestamp:
            if first_conditional:
                query += " WHERE"
            else:
                query += " AND"
            first_conditional = False
            query += " timestamp <= ?"
            params.append(end_timestamp)

        if client:
            if first_conditional:
                query += " WHERE"
            else:
                query += " AND"
            query += " local = ?"
            params.append(client)

        return query, params

    @staticmethod
    def add_condition(query: str, params: list, condition: str, value) -> str:
        """Append one more condition: WHERE if the query has none yet, else AND."""
        query += (" AND " if " WHERE " in query else " WHERE ") + condition
        params.append(value)
        return query

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Report network traffic.")
    parser.add_argument('--db_path', default=os.getenv('DB_PATH', '../styx-dpi/data/styx-dpi.db'), help='Path to SQLite3 database (default: data/styx-dpi.db)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--host', default=os.getenv('HOST', '0.0.0.0'), help='Address to listen for connections')
    parser.add_argument('--port', default=int(os.getenv('PORT', '8192')), help='Port to listen for connections')
    args = parser.parse_args()

    if args.debug:
        try:
            import pydevd_pycharm
            pydevd_pycharm.settrace('127.0.0.1', port=12345, stdoutToServer=True, stderrToServer=True, suspend=False)
        except ModuleNotFoundError as e:
            print("IntelliJ debugger not available")

    api = TrafficAPI(database_path=args.db_path)
    uvicorn.run(api.app, host=args.host, port=args.port)
