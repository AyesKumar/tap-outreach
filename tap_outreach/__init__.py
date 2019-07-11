#!/usr/bin/env python3
import datetime
import pytz
import itertools
import os
import re
import sys
import json

import backoff
import requests
import singer
import singer.messages
import singer.metrics as metrics
from singer import metadata
from singer import utils
from singer import (transform,
                    UNIX_MILLISECONDS_INTEGER_DATETIME_PARSING,
                    Transformer, _transform_datetime)

REQUIRED_CONFIG_KEYS = ["redirect_uri",
                        "client_id",
                        "client_secret",
                        "refresh_token",
                        "start_date"]
LOGGER = singer.get_logger()

BASE_URL = "https://api.outreach.io/api"

CONFIG = {
    "access_token": None,
    "token_expires": None,

    # in config.json
    "redirect_uri": None,
    "client_id": None,
    "client_secret": None,
    "refresh_token": None,
    "start_date": None
}

ENDPOINTS = {
    "audit":                        "/v2/audits",
    "account":                      "/v2/accounts",
    "call_dispositions":            "/v2/callDispositions",
    "call_purposes":                "/v2/callPurposes",
    "calls":                        "/v2/calls",
    "email_addresses":              "/v2/emailAddresses",
    "mailings":                     "/v2/mailings",
    "opportunities":                "/v2/opportunities",
    "prospects":                    "/v2/prospects",
    "sequence_states":              "/v2/sequenceStates",
    "sequence_steps":               "/v2/sequenceSteps",
    "sequences":                    "/v2/sequences",
    "stages":                       "/v2/stages"
}


def acquire_access_token_from_refresh_token():
    payload = {
        "grant_type": "refresh_token",
        "redirect_uri": CONFIG['redirect_uri'],
        "refresh_token": CONFIG['refresh_token'],
        "client_id": CONFIG['client_id'],
        "client_secret": CONFIG['client_secret'],
    }

    resp = requests.post("https://api.outreach.io/oauth/token", data=payload)
    if resp.status_code == 403:
        raise InvalidAuthException(resp.content)

    resp.raise_for_status()
    auth = resp.json()
    CONFIG['access_token'] = auth['access_token']
    CONFIG['refresh_token'] = auth['refresh_token']
    CONFIG['token_expires'] = (
        datetime.datetime.utcnow() +
        datetime.timedelta(seconds=auth['expires_in'] - 600))
    LOGGER.info("Token refreshed. Expires at %s", CONFIG['token_expires'])

'''
def get_start(state, tap_stream_id, bookmark_key):
    current_bookmark = singer.get_bookmark(state, tap_stream_id, bookmark_key)
    if current_bookmark is None:
        return CONFIG['start_date']
    return current_bookmark


def has_bookmark(state, tap_stream_id, bookmark_key):
    return singer.get_bookmark(state, tap_stream_id, bookmark_key) is not None


def get_previous_time_window(state, tap_stream_id):
    return singer.get_bookmark(state, tap_stream_id, "last_sync_duration")


def write_stream_duration(state, tap_stream_id, start, end):
    duration = (end - start).total_seconds()
    return singer.write_bookmark(state, tap_stream_id, "last_sync_duration", duration)


def get_url(endpoint, **kwargs):
    if endpoint not in ENDPOINTS:
        raise ValueError("Invalid endpoint {}".format(endpoint))

    return BASE_URL + ENDPOINTS[endpoint].format(**kwargs)
'''

def get_abs_path(path):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), path)

# Load schemas from schemas folder
def load_schemas():
    schemas = {}

    for filename in os.listdir(get_abs_path('schemas')):
        path = get_abs_path('schemas') + '/' + filename
        file_raw = filename.replace('.json', '')
        with open(path) as file:
            schemas[file_raw] = json.load(file)

    return schemas

def discover():
    raw_schemas = load_schemas()
    streams = []

    for schema_name, schema in raw_schemas.items():

        # TODO: populate any metadata and stream's key properties here..
        stream_metadata = []
        stream_key_properties = []

        # create and add catalog entry
        catalog_entry = {
            'stream': schema_name,
            'tap_stream_id': schema_name,
            'schema': schema,
            'metadata' : [],
            'key_properties': []
        }
        streams.append(catalog_entry)

    return {'streams': streams}

def get_selected_streams(catalog):
    '''
    Gets selected streams.  Checks schema's 'selected' first (legacy)
    and then checks metadata (current), looking for an empty breadcrumb
    and mdata with a 'selected' entry
    '''
    selected_streams = []
    for stream in catalog.streams:
        stream_metadata = metadata.to_map(stream.metadata)
        # stream metadata will have an empty breadcrumb
        if metadata.get(stream_metadata, (), "selected"):
            selected_streams.append(stream.tap_stream_id)

    return selected_streams

def sync(config, state, catalog):

    selected_stream_ids = get_selected_streams(catalog)

    # Loop over streams in catalog
    for stream in catalog.streams:
        stream_id = stream.tap_stream_id
        stream_schema = stream.schema
        if stream_id in selected_stream_ids:
            # TODO: sync code for stream goes here...
            LOGGER.info('Syncing stream:' + stream_id)

            querystring = {"sort": "-updatedAt",
                            "page[limit]": "100",
                            "filter[updatedAt]": start_date + ".." + end_date}


    return

@backoff.on_exception(backoff.constant,
                      (requests.exceptions.RequestException,
                       requests.exceptions.HTTPError),
                      max_tries=5,
                      jitter=None,
                      giveup=giveup,
                      on_giveup=on_giveup,
                      interval=10)
def request(url, params=None):

    params = params or {}
    if CONFIG['token_expires'] is None or CONFIG['token_expires'] < datetime.datetime.utcnow():
        acquire_access_token_from_refresh_token()
    headers = {
        'Content-Type': "application/vnd.api+json",
        'Authorization': "Bearer " + CONFIG["access_token"]
        }

    if 'user_agent' in CONFIG:
        headers['User-Agent'] = CONFIG['user_agent']

    req = requests.Request('GET', url, params=params, headers=headers).prepare()
    LOGGER.info("GET %s", req.url)
    with metrics.http_request_timer(parse_source_from_url(url)) as timer:
        resp = SESSION.send(req)
        timer.tags[metrics.Tag.http_status_code] = resp.status_code
        if resp.status_code == 403:
            raise SourceUnavailableException(resp.content)
        else:
            resp.raise_for_status()

    return resp

#pylint: disable=line-too-long
def gen_request(STATE, tap_stream_id, url, params, path, more_key, offset_keys, offset_targets):
    if len(offset_keys) != len(offset_targets):
        raise ValueError("Number of offset_keys must match number of offset_targets")

    if singer.get_offset(STATE, tap_stream_id):
        params.update(singer.get_offset(STATE, tap_stream_id))

    with metrics.record_counter(tap_stream_id) as counter:
        while True:
            data = request(url, params).json()

            for row in data[path]:
                counter.increment()
                yield row

            if not data.get(more_key, False):
                break

            STATE = singer.clear_offset(STATE, tap_stream_id)
            for key, target in zip(offset_keys, offset_targets):
                if key in data:
                    params[target] = data[key]
                    STATE = singer.set_offset(STATE, tap_stream_id, target, data[key])

            singer.write_state(STATE)

    STATE = singer.clear_offset(STATE, tap_stream_id)
    singer.write_state(STATE)

STREAMS = [
    # Do these first as they are incremental

    # Do these last as they are full table
    Stream('prospects', sync_prospects, ['id'], 'updatedAt', 'FULL_TABLE'),
    Stream('sequences', sync_sequences, ['id'], 'updatedAt', 'FULL_TABLE'),
]

@utils.handle_top_exception(LOGGER)
def main():

    # Parse command line arguments
    args = utils.parse_args(REQUIRED_CONFIG_KEYS)

    CONFIG.update(args.config)
    acquire_access_token_from_refresh_token()

    # If discover flag was passed, run discovery mode and dump output to stdout
    if args.discover:
        catalog = discover()
        print(json.dumps(catalog, indent=2))
    # Otherwise run in sync mode
    else:
        if args.catalog:
            catalog = args.catalog
        else:
            catalog =  discover()

        sync(CONFIG, args.state, catalog)

if __name__ == "__main__":
    main()
