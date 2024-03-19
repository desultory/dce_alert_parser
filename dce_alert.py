__version__ = '0.6.1'
__author__ = 'desultory'

import re

from enum import Enum


def validate_ip(value):
    """ Returns true if the ip is valid. """
    from ipaddress import IPv4Address
    if IPv4Address(value):
        return True


class AlertTypes(Enum):
    Unknown = {'conditions': None}
    TestPOST = {'string': '<struct-element fieldid="errortype"><varid-val>nbErrorType_test</varid-val>'}
    CommunicationLoss = {'string': '<struct-element fieldid="errortype"><varid-val>nbErrorType_podunpluggedsensor</varid-val></struct-element>'}
    ValueTooHigh = {'string': '<struct-element fieldid="errortype"><varid-val>nbErrorType_toohigh</varid-val></struct-element>',
                    'value_regex': r'<struct-element fieldid="parm_0"><string-val>([0-9\.]+)</string-val></struct-element>'}
    ValueTooLow = {'string': '<struct-element fieldid="errortype"><varid-val>nbErrorType_toolow</varid-val></struct-element>',
                   'value_regex': r'<struct-element fieldid="parm_0"><string-val>([0-9\.]+)</string-val></struct-element>'}
    DeviceAlarm = {'string': '<struct-element fieldid="errortype"><varid-val>nbErrorType_devicealarm</varid-val></struct-element',
                   'value_regex': r'<struct-element fieldid="parm_0"><nls-string-val raw="[^>]+">([^<]+)<\/nls-string-val><\/struct-element>'}
    ErrorState = {'string': '<struct-element fieldid="errortype"><varid-val>nbErrorType_errorstate</varid-val></struct-element>',
                  'value_regex': r'<struct-element fieldid="policyblock"><varid-val>([^<]+)<\/varid-val><\/struct-element>'}


class AlertValues(Enum):
    # The order of these values is important, as some values reference other values.
    serial_number = {'regex': r'<metadata slotid="nbSerialNum"><string-val>([0-9a-fA-F:]+)<\/string-val><\/metadata>',
                     'required': True}
    server_ip = {'regex': r'<struct-element fieldid="ip"><string-val>([0-9\.]*)<\/string-val><\/struct-element>',
                 'required': True,
                 'validate': 'ip'}
    mac_address = {'regex': r'<metadata slotid="nbProductData"><struct-val>(?!.*<string-val>StruxureWare Data Center Expert</string-val>).*<struct-element fieldid="mac_addr"><string-val>([0-9a-fA-F:]+)</string-val></struct-element>'}
    device_ip = {'regex': [r'<metadata slotid="nbLabel"><nls-string-val raw="([0-9\.]*)">([0-9\.]+?)<\/nls-string-val><\/metadata>',
                           r'<metadata slotid="nbLabel"><nls-string-val raw="%{scannerDDFMsg\|%s - Slave %s\|([^>]+)\|[0-9]+%}">[^>]+><\/metadata>',
                           r'<metadata slotid="nbLabel"><nls-string-val raw="%{scannerDDFMsg\|%s \(%s\)\|[^|]+\|([^>]+)%}">[^>]+><\/metadata>'],
                 'validate': 'ip'}
    device_serial = {'regex': '<metadata slotid="nbProductData"><struct-val>(?!.*<string-val>StruxureWare Data Center Expert</string-val>).+<struct-element fieldid="serial_num"><string-val>([a-zA-Z0-9]+)</string-val></struct-element>'}
    hostname = {'regex': r'<metadata slotid="nbLabel"><nls-string-val raw="%{scannerDDFMsg\|%s[^|]*\|([^|]*)\|[^>]+>[^>]+><\/metadata><\/variable>'}
    location = {'regex': r'<metadata slotid="nbLocationData"><struct-val>.*<struct-element fieldid="LOCATION"><string-val>([^<]+)</string-val></struct-element>'}
    vendor = {'regex': r'<metadata slotid="nbProductData"><struct-val>.*<struct-element fieldid="vendor"><string-val>([^<]+)</string-val></struct-element>'}
    model = {'regex': r'<metadata slotid="nbProductData"><struct-val>.*<struct-element fieldid="model"><string-val>([^<]+)</string-val></struct-element>'}
    node_type = {'regex': r'<metadata slotid="nbProductData"><struct-val>.*<struct-element fieldid="type"><string-val>([^<]+)</string-val></struct-element>'}
    sysname = {'regex': r'<metadata slotid="nbLocationData"><struct-val>.*<struct-element fieldid="SYSNAME"><string-val>([^<]+)</string-val></struct-element>'}
    return_to_normal = {'string': '<variable varid="nbAlertSched" class="nbAlertSchedInfo" classpath="/nbAlertSchedInfo"><nls-string-val raw="Return To Normal">Return To Normal</nls-string-val></variable>'}
    alert_level = {'regex': r'<struct-element fieldid="severity"><string-val>(\w+)<\/string-val><\/struct-element>'}
    notification_group = {'regex': r'<metadata slotid="nbLabel"><nls-string-val raw="([^"]+)">[^<]+<\/nls-string-val><\/metadata><\/variable><\/variable-set>'}
    action_name = {'regex': r'<variable varid="nbAlertSched" class="nbAlertSchedInfo" classpath="/nbAlertSchedInfo"><nls-string-val raw="[^"]+">(.*?)(?:\s-\srepeat\s\d+)?</nls-string-val></variable>'}
    repeat = {'regex': r'<variable varid="nbAlertSched" class="nbAlertSchedInfo" classpath="/nbAlertSchedInfo"><nls-string-val raw="[^"]+">[^<]+ - repeat (\d+)</nls-string-val></variable>'}
    timestamp = {'regex': r'<variable-set timestamp="(\d+)" '}


class DCEAlert:
    def __init__(self, xml_data):
        self.xml_data = xml_data
        self.parse_xml()

    def parse_value(self, alert_value):
        """ Parses alert values based on the name in the passed string. """
        detected_value = None
        # First attempt regex detection
        if 'regex' in alert_value.value:
            # For multiple matches, get group 1
            if isinstance(alert_value.value['regex'], list):
                for regex_parameter in alert_value.value['regex']:
                    # Try all regex parameters for this alert type
                    try:
                        detected_value = re.search(regex_parameter, self.xml_data).group(1)
                    except AttributeError:
                        continue
                    break
                else:
                    # If no matches are found, raise an error
                    raise AttributeError("Unable to parse parameter: %s" % alert_value.name)
                if not detected_value:
                    # Check if it's a test post here
                    if self.alert_type is AlertTypes.TestPOST:
                        return
                    elif alert_value.name == 'device_ip':
                        raise ValueError("Alert detected with no device IP info")
                        detected_value = self.server_ip
                    else:
                        raise AttributeError("Unable to parse parameter: %s" % alert_value.name)
            # Single regex match
            else:
                # Try to get group 1, throw an error if it's a required value
                try:
                    detected_value = re.search(alert_value.value['regex'], self.xml_data).group(1)
                except AttributeError:
                    if alert_value.value.get('required'):
                        raise ValueError("Unable to parse required value: %s" % alert_value)
                    else:
                        return
        # String based detection, sets the value to true if the string is detected
        elif 'string' in alert_value.value:
            detected_value = False
            # If it's a list of strings, try each one
            if isinstance(alert_value.value['string'], list):
                for detection_string in alert_value.value['string']:
                    if detection_string in self.xml_data:
                        detected_value = True
            elif alert_value.value['string'] in self.xml_data:
                detected_value = True

        # Validate if needed
        if validate_type := globals().get(f"validate_{alert_value.value.get('validate')}"):
            if not validate_type(detected_value):
                raise ValueError("Failed to validate parameter: %s" % detected_value)

        setattr(self, alert_value.name, detected_value)

    def parse_type(self, alert_type):
        """
        Attempts to detect the alert type basd on the 'XML' payload.
        Attempt to extract the alert value for values types with a defined 'value_regex'
        """
        if alert_string := alert_type.value.get('string'):
            if alert_string in self.xml_data:
                self.alert_type = alert_type
                if 'value_regex' in alert_type.value:
                    self.alert_value = re.search(alert_type.value['value_regex'], self.xml_data).group(1)

    def parse_xml(self):
        """ Attempts to parse data from a DCE XML post. """
        # First attempt to process the alert type
        for alert_type in AlertTypes:
            self.parse_type(alert_type)

        # Attempt to parse device information
        # Iterate through the enum values
        for alert_value in AlertValues:
            self.parse_value(alert_value)

        # If the hostname is not set, use the device IP
        if not self.hostname:
            self.hostname = self.device_ip

    def to_json(self):
        """ Returns the object as a JSON string. """
        import json
        data = {'alert_type': self.alert_type.name}
        for parameter in AlertValues.__members__:
            if value := getattr(self, parameter, None):
                if parameter == 'alert_type':
                    data[parameter] = value.name
                else:
                    data[parameter] = value
        return json.dumps(data)
