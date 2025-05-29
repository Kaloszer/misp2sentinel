from pymisp import PyMISP
from pymisp import ExpandedPyMISP
import MISP2Sentinel.config as config
from collections import defaultdict
from MISP2Sentinel.RequestManager import RequestManager
from MISP2Sentinel.RequestObject import RequestObject, RequestObject_Event, RequestObject_Indicator
from MISP2Sentinel.constants import *
import sys
from functools import reduce
import os
import datetime
from datetime import datetime, timedelta, timezone
import logging
import azure.functions as func
import requests
import json
from misp_stix_converter import MISPtoSTIX21Parser
from stix2.base import STIXJSONEncoder

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _get_events():
    """Legacy function for Graph API compatibility"""
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert)
    if len(config.misp_event_filters) == 0:
        return [event['Event'] for event in misp.search(controller='events', return_format='json')]
    events_for_each_filter = [
        [event['Event'] for event in misp.search(controller='events', return_format='json', **config.misp_event_filters)]
    ]
    event_ids_for_each_filter = [set(event['id'] for event in events) for events in events_for_each_filter]
    event_ids_intersection = reduce((lambda x, y: x & y), event_ids_for_each_filter)
    return [event for event in events_for_each_filter[0] if event['id'] in event_ids_intersection]

def _graph_post_request_body_generator(parsed_events):
    """Graph API request body generator for legacy compatibility"""
    for event in parsed_events:
        request_body_metadata = {
            **{field: event[field] for field in REQUIRED_GRAPH_METADATA},
            **{field: event[field] for field in OPTIONAL_GRAPH_METADATA if field in event},
            'action': config.ms_action,
            'passiveOnly': config.ms_passiveonly,
            'targetProduct': config.ms_target_product,
        }

        if len(request_body_metadata.get('threatType', [])) < 1:
            request_body_metadata['threatType'] = 'watchlist'
        if config.default_confidence:
            request_body_metadata["confidence"] = config.default_confidence
        for request_object in event['request_objects']:
            request_body = {
                **request_body_metadata.copy(),
                **request_object.__dict__,
                'tags': request_body_metadata.copy()['tags'] + request_object.__dict__['tags'],
            }
            yield request_body

def _handle_timestamp(parsed_event):
    """Handle timestamp conversion for Graph API"""
    parsed_event['lastReportedDateTime'] = str(
        datetime.fromtimestamp(int(parsed_event['lastReportedDateTime'])))

def _handle_diamond_model(parsed_event):
    """Handle diamond model parsing for Graph API"""
    for tag in parsed_event['tags']:
        if 'diamond-model:' in tag:
            parsed_event['diamondModel'] = tag.split(':')[1]

def _handle_tlp_level(parsed_event):
    """Handle TLP level parsing for Graph API"""
    for tag in parsed_event['tags']:
        if 'tlp:' in tag:
            parsed_event['tlpLevel'] = tag.split(':')[1].lower().capitalize()
        if parsed_event['tlpLevel'] == 'Clear':
            parsed_event['tlpLevel'] = 'White'
    if 'tlpLevel' not in parsed_event:
        parsed_event['tlpLevel'] = 'Red'

def _get_misp_events_stix():
    misp = ExpandedPyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    result_set = []
    logging.debug("Query MISP for events.")
    remaining_misp_pages = True
    misp_page = 1
    misp_indicator_ids = []
    total_pages = None

    while remaining_misp_pages:
        try:
            logging.info(f"Processing MISP page {misp_page}" + (f" of ~{total_pages}" if total_pages else ""))
            if "limit" in config.misp_event_filters:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters)
            else:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

            if len(result) > 0:
                # Calculate estimated total pages on first result
                if total_pages is None and "limit" not in config.misp_event_filters:
                    # Assuming the first page is representative of the total number of events
                    total_pages = (len(result) + config.misp_event_limit_per_page - 1) // config.misp_event_limit_per_page
                    logging.info(f"Estimated total pages: {total_pages}")

                logging.info("Received MISP events page {} with {} events".format(misp_page, len(result)))
                for index, event in enumerate(result):
                    logging.info("Processing event {}".format(index + 1))
                    misp_event = RequestObject_Event(event["Event"])
                    parser = MISPtoSTIX21Parser()
                    parser.parse_misp_event(event)
                    stix_objects = parser.stix_objects
                    for element in stix_objects:
                        if element.type in UPLOAD_INDICATOR_API_ACCEPTED_TYPES and \
                                        element.id not in misp_indicator_ids:
                            misp_indicator = RequestObject_Indicator(element, misp_event)
                            if misp_indicator.id:
                                if misp_indicator.valid_until:
                                    valid_until = json.dumps(misp_indicator.valid_until, cls=STIXJSONEncoder).replace("\"", "")
                                    if "Z" in valid_until:
                                        date_object = datetime.fromisoformat(valid_until[:-1])
                                    elif "." in valid_until:
                                        date_object = datetime.fromisoformat(valid_until.split(".")[0])
                                    else:
                                        date_object = datetime.fromisoformat(valid_until)
                                    if date_object > datetime.now():
                                        if config.verbose_log:
                                            logging.debug("Add {} to list of indicators to upload".format(misp_indicator.pattern))
                                        misp_indicator_ids.append(misp_indicator.id)
                                        result_set.append(misp_indicator._get_dict())
                                    else:
                                        logging.error("Skipping outdated indicator {}, valid_until: {}".format(misp_indicator.pattern, valid_until))
                                else:
                                    logging.error("Skipping indicator because valid_until was not set by MISP/MISP2Sentinel {}".format(misp_indicator.id))
                            else:
                                logging.error("Unable to process indicator")
                logging.debug("Processed {} indicators.".format(len(result_set)))
                misp_page += 1
            else:
                logging.info("No more events to process.")
                remaining_misp_pages = False

        except Exception as e:
            remaining_misp_pages = False
            logging.error("Error when processing data from MISP {}".format(e))
    logging.info("Finished processing MISP events. Returning {} indicators in result set.".format(len(result_set)))
    return result_set, len(result_set)
def _init_configuration():
    """Configuration initialization and backward compatibility checks"""
    config_mapping = {
        "graph_auth": "ms_auth",
        "targetProduct": "ms_target_product",
        "action": "ms_action",
        "passiveOnly": "ms_passiveonly",
        "defaultConfidenceLevel": "default_confidence"
    }

    use_old_config = False
    for old_value in config_mapping:
        if hasattr(config, old_value):
            p = getattr(config, old_value)
            setattr(config, config_mapping[old_value], p)
            use_old_config = True

    # Essential configuration checks
    if not hasattr(config, "log_file"):
        config.log_file = "misp2sentinel.log"  # Default instead of exit
    if not (hasattr(config, "misp_domain") and hasattr(config, "misp_key") and hasattr(config, "misp_verifycert")):
        logging.error("Missing MISP authentication configuration (misp_domain, misp_key and misp_verifycert).")
        if hasattr(config, "log_file"):
            return use_old_config  # Allow to continue in Azure Functions
        else:
            import sys
            sys.exit("Exiting. No MISP authentication configuration setting found.")
    if not hasattr(config, "ms_auth"):
        logging.error("Missing Microsoft authentication configuration (ms_auth).")
        if hasattr(config, "log_file"):
            return use_old_config  # Allow to continue in Azure Functions
        else:
            import sys
            sys.exit("Exiting. No Microsoft authentication configuration setting found.")
    
    # Set defaults for optional settings
    if not hasattr(config, "ms_useragent"):
        config.ms_useragent = "MISP-1.0"
    if not hasattr(config, "default_confidence"):
        config.default_confidence = 50
    if not hasattr(config, "ms_passiveonly"):
        config.ms_passiveonly = False
    if not hasattr(config, "ms_target_product"):
        config.ms_target_product = "Azure Sentinel"
    if not hasattr(config, "ms_action"):
        config.ms_action = "alert"
    if not hasattr(config, "misp_event_limit_per_page"):
        config.misp_event_limit_per_page = 100
    if not hasattr(config, "days_to_expire_ignore_misp_last_seen"):
        config.days_to_expire_ignore_misp_last_seen = False
    if not hasattr(config, "misp_remove_eventreports"):
        config.misp_remove_eventreports = True
    if not hasattr(config, "sentinel_write_response"):
        config.sentinel_write_response = False
    if not hasattr(config, "write_parsed_eventid"):
        config.write_parsed_eventid = False
    if not hasattr(config, "misp_flatten_attributes"):
        config.misp_flatten_attributes = False
    if not hasattr(config, "sourcesystem"):
        config.sourcesystem = "MISP"
    if not hasattr(config, "dry_run"):
        config.dry_run = False

    return use_old_config

def _build_logger():
    """Enhanced logger building with Azure Functions compatibility"""
    logger = logging.getLogger("misp2sentinel")
    logger.setLevel(logging.INFO)
    if hasattr(config, 'verbose_log') and config.verbose_log:
        logger.setLevel(logging.DEBUG)
    
    # In Azure Functions, console logging is often preferred
    if hasattr(config, "log_file") and config.log_file:
        try:
            ch = logging.FileHandler(config.log_file, mode="a")
        except:
            # Fallback to console logging in Azure Functions
            ch = logging.StreamHandler()
            raise
    else:
        ch = logging.StreamHandler()
    
    ch.setLevel(logging.INFO)
    if hasattr(config, 'verbose_log') and config.verbose_log:
        ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

def push_to_sentinel(tenant, id, secret, workspace, parsed_indicators=None, total_indicators=None, logger=None):
    """Enhanced push_to_sentinel supporting both logging approaches and multi-tenant optimization"""
    # Use provided logger or standard logging
    log_func = logger.info if logger else logging.info
    log_error = logger.error if logger else logging.error
    log_debug = logger.debug if logger else logging.debug
    
    # Check if Graph API mode is configured and enabled
    if hasattr(config, 'ms_auth') and config.ms_auth.get("graph_api", False):
        log_func("Using Microsoft Graph API")
        events = _get_events()
        parsed_events = list()
        for event in events:
            parsed_event = defaultdict(list)

            for key, mapping in EVENT_MAPPING.items():
                parsed_event[mapping] = event.get(key, "")

            # Tags on event level
            tags = []
            for tag in event.get("Tag", []):
                if 'sentinel-threattype' in tag['name']:    # Can be overridden on attribute level
                    parsed_event['threatType'] = tag['name'].split(':')[1]
                    continue
                if hasattr(config, 'ignore_localtags') and config.ignore_localtags:
                    if tag["local"] != 1:
                        tags.append(tag['name'].strip())
            parsed_event['tags'] = tags
            _handle_diamond_model(parsed_event)
            _handle_tlp_level(parsed_event)
            _handle_timestamp(parsed_event)

            for attr in event['Attribute']:
                if attr['type'] == 'threat-actor':
                    parsed_event['activityGroupNames'].append(attr['value'])
                if attr['type'] == 'comment':
                    parsed_event['description'] += attr['value']
                if attr['type'] in MISP_ACTIONABLE_TYPES and attr['to_ids'] == True:
                    parsed_event['request_objects'].append(RequestObject(attr, parsed_event['description']))
            for obj in event['Object']:
                for attr in obj['Attribute']:
                    if attr['type'] == 'threat-actor':
                        parsed_event['activityGroupNames'].append(attr['value'])
                    if attr['type'] == 'comment':
                        parsed_event['description'] += attr['value']
                    if attr['type'] in MISP_ACTIONABLE_TYPES and attr['to_ids'] == True:
                        parsed_event['request_objects'].append(RequestObject(attr, parsed_event['description']))
            parsed_events.append(parsed_event)
        del events
        total_indicators = sum([len(v['request_objects']) for v in parsed_events])
        
        # Process with Graph API
        if hasattr(config, 'dry_run') and config.dry_run:
            log_func("Dry run. Not uploading to Sentinel")
        else:    
            with RequestManager(total_indicators, logger, tenant) as request_manager:
                for request_body in _graph_post_request_body_generator(parsed_events):
                    if hasattr(config, 'verbose_log') and config.verbose_log:
                        log_debug("request body: {}".format(request_body))
                    request_manager.handle_indicator(request_body)
    else:
        # Use Microsoft Upload Indicator API (your optimization)
        log_func("Using Microsoft Upload Indicator API")
        config.ms_auth[TENANT] = tenant
        config.ms_auth[CLIENT_ID] = id
        config.ms_auth[CLIENT_SECRET] = secret
        config.ms_auth[WORKSPACE_ID] = workspace
        log_func(f"Tenant: {tenant}")
        log_func(f"Client ID: {id}")
        log_func(f"Workspace ID: {workspace}")
        log_func(f"Secret:{secret[:2] + '*' * (len(secret) - 8) + secret[-2:]}")
        
        # Only fetch from MISP if indicators weren't provided (your optimization)
        if parsed_indicators is None or total_indicators is None:
            parsed_indicators, total_indicators = _get_misp_events_stix()
            log_func("Found {} indicators in MISP".format(total_indicators))
        else:
            log_func("Using {} cached indicators from previous fetch".format(total_indicators))

        if hasattr(config, 'dry_run') and config.dry_run:
            log_func("Dry run. Not uploading to Sentinel")
        else:
            with RequestManager(total_indicators, logger, tenant) as request_manager:
                log_func("Start uploading indicators")
                request_manager.upload_indicators(parsed_indicators)
                log_func("Finished uploading indicators")
                if hasattr(config, 'write_parsed_indicators') and config.write_parsed_indicators:
                    json_formatted_str = json.dumps(parsed_indicators, indent=4)
                    with open("parsed_indicators.txt", "w") as fp:
                        fp.write(json_formatted_str)

def pmain(logger=None):
    """Enhanced pmain supporting both single and multi-tenant modes with optimization"""
    # Multi-tenant mode with optimization
    tenants_env = os.getenv('tenants', '')
    if tenants_env:
        tenants = json.loads(tenants_env)
        
        # Fetch indicators once for all tenants
        log_func = logger.info if logger else logging.info
        log_func("Fetching MISP indicators once for all tenants")
        parsed_indicators, total_indicators = _get_misp_events_stix()
        log_func("Found {} indicators in MISP".format(total_indicators))
        
        # Reuse the same indicators for each tenant
        for item in tenants:
            push_to_sentinel(
                item['tenantId'], 
                item['id'], 
                item['secret'], 
                item['workspaceId'],
                parsed_indicators,
                total_indicators,
                logger
            )
    else:
        # Single-tenant mode
        if hasattr(config, 'ms_auth'):
            tenant = config.ms_auth.get(TENANT)
            id = config.ms_auth.get(CLIENT_ID)
            secret = config.ms_auth.get(CLIENT_SECRET)
            workspace = config.ms_auth.get(WORKSPACE_ID)
            push_to_sentinel(tenant, id, secret, workspace, logger=logger)

def main(mytimer: func.TimerRequest) -> None:
    """Enhanced main function with proper configuration and logging setup"""
    # Initialize configuration (from open source)
    check_for_old_config = _init_configuration()
    
    # Build logger (from open source, enhanced for Azure Functions)
    logger = _build_logger()

    utc_timestamp = datetime.utcnow().replace(
        tzinfo=timezone.utc).isoformat()

    if mytimer.past_due:
        logger.info('The timer is past due!')

    logger.info("Start MISP2Sentinel")
    if check_for_old_config:
        logger.info("You're using an older configuration setting. Update config.py to the new configuration setting.")
    pmain(logger)
    logger.info("End MISP2Sentinel")
    logger.info('Python timer trigger function ran at %s', utc_timestamp)
