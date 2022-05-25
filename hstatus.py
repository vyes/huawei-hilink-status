#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
import xmltodict
import requests
import time
import math
import json

def to_size(size):
   if (size == 0):
       return '0 Bytes'
   size_name = ('Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
   i = int(math.floor(math.log(size,1024)))
   p = math.pow(1024,i)
   s = round(size/p,2)
   return '%s %s' % (s,size_name[i])


def is_hilink(device_ip):
    try:
        r = requests.get(url='http://' + device_ip + '/api/device/information', allow_redirects=False, timeout=(2.0,2.0))
    except requests.exceptions.RequestException as e:
        return False;

    if r.status_code != 200:
        return False
    return True

def login(session, device_ip):
    try:
        r = session.get(url='http://' + device_ip + '/api/webserver/SesTokInfo', allow_redirects=False, timeout=(2.0,2.0))
        #print(r.content)
    except requests.exceptions.RequestException as e:
        return token
    try:
        d = xmltodict.parse(r.text, xml_attribs=True)
        #print(d)
        if 'response' in d and 'TokInfo' in d['response'] and 'SesInfo' in d['response'] and d['response']['SesInfo'].startswith('SessionID='):
            return {'token': d['response']['TokInfo'], 'session': d['response']['SesInfo'][10:]}
    except:
        raise Exception('Received error code ' + d['error']['code'] + ' for URL ' + r.url)
    

def call_api(session, device_ip, token, resource, xml_attribs=True):
    headers = {}
    if token is not None:
        headers = {'__RequestVerificationToken': token}
    try:
        r = session.get(url='http://' + device_ip + resource, headers=headers, allow_redirects=False, timeout=(2.0,2.0))
    except requests.exceptions.RequestException as e:
        print ("Error: "+str(e))
        return False;

    if r.status_code == 200:
        d = xmltodict.parse(r.text, xml_attribs=xml_attribs)
        if 'error' in d:
            raise Exception('Received error code ' + d['error']['code'] + ' for URL ' + r.url)
        return d['response']
    else:
        raise Exception('Received status code ' + str(r.status_code) + ' for URL ' + r.url)

def get_connection_status(status):
    result = 'n/a'
    if status == '2' or status == '3' or status == '5' or status == '8' or status == '20' or status == '21' or status == '23' or status == '27' or status == '28' or status == '29' or status == '30' or status == '31' or status == '32' or status == '33':
        result = 'Connection failed, the profile is invalid'
    elif status == '7' or status == '11' or status == '14' or status == '37':
        result = 'Network access not allowed'
    elif status == '12' or status == '13':
        result = 'Connection failed, roaming not allowed'
    elif status == '201':
        result = 'Connection failed, bandwidth exceeded'
    elif status == '900':
        result = 'Connecting'
    elif status == '901':
        result = 'Connected'
    elif status == '902':
        result = 'Disconnected'
    elif status == '903':
        result = 'Disconnecting'
    elif status == '904':
        result = 'Connection failed or disabled'
    return result

def get_network_type(type):
    result = 'n/a'
    if type == '0':
        result = 'No Service'
    elif type == '1':
        result = 'GSM'
    elif type == '2':
        result = 'GPRS (2.5G)'
    elif type == '3':
        result = 'EDGE (2.75G)'
    elif type == '4':
        result = 'WCDMA (3G)'
    elif type == '5':
        result = 'HSDPA (3G)'
    elif type == '6':
        result = 'HSUPA (3G)'
    elif type == '7':
        result = 'HSPA (3G)'
    elif type == '8':
        result = 'TD-SCDMA (3G)'
    elif type == '9':
        result = 'HSPA+ (4G)'
    elif type == '10':
        result = 'EV-DO rev. 0'
    elif type == '11':
        result = 'EV-DO rev. A'
    elif type == '12':
        result = 'EV-DO rev. B'
    elif type == '13':
        result = '1xRTT'
    elif type == '14':
        result = 'UMB'
    elif type == '15':
        result = '1xEVDV'
    elif type == '16':
        result = '3xRTT'
    elif type == '17':
        result = 'HSPA+ 64QAM'
    elif type == '18':
        result = 'HSPA+ MIMO'
    elif type == '19':
        result = 'LTE (4G)'
    elif type == '41':
        result = 'UMTS (3G)'
    elif type == '44':
        result = 'HSPA (3G)'
    elif type == '45':
        result = 'HSPA+ (3G)'
    elif type == '46':
        result = 'DC-HSPA+ (3G)'
    elif type == '64':
        result = 'HSPA (3G)'
    elif type == '65':
        result = 'HSPA+ (3G)'
    elif type == '101':
        result = 'LTE (4G)'
    return result

def get_roaming_status(status):
    result = 'n/a'
    if status == '0':
        result = 'Disabled'
    elif status == '1':
        result = 'Enabled'
    return result

def get_signal_level(level):
    result = '-'
    if level == '1':
        result = u'\u2581'
    if level == '2':
        result = u'\u2581' + u'\u2583'
    if level == '3':
        result = u'\u2581' + u'\u2583' + u'\u2584'
    if level == '4':
        result = u'\u2581' + u'\u2583' + u'\u2584' + u'\u2586'
    if level == '5':
        result = u'\u2581' + u'\u2583' + u'\u2584' + u'\u2586' + u'\u2588'
    return result

def print_traffic_statistics(session, device_ip, token, connection_status):
    d = call_api(session, device_ip, token, '/api/monitoring/traffic-statistics')
    #print(json.dumps(d, indent=4))
    current_connect_time = d['CurrentConnectTime']
    current_upload = d['CurrentUpload']
    current_download = d['CurrentDownload']
    total_upload = d['TotalUpload']
    total_download = d['TotalDownload']

    if connection_status == '901':
        print('    Connected for: ' + time.strftime('%H:%M:%S', time.gmtime(float(current_connect_time))) + ' (hh:mm:ss)')
        print('    Downloaded: ' + to_size(float(current_download)))
        print('    Uploaded: ' + to_size(float(current_upload)))
    print('  Total downloaded: ' + to_size(float(total_download)))
    print('  Total uploaded: ' + to_size(float(total_upload)))

def print_connection_status(session, device_ip, token):
    d = call_api(session, device_ip, token, '/api/monitoring/status')
    #print(json.dumps(d, indent=4))
    connection_status = d['ConnectionStatus']
    signal_strength = d['SignalStrength']
    signal_level = d['SignalIcon']
    network_type = d['CurrentNetworkType']
    roaming_status = d['RoamingStatus']
    primary_dns_ip = d['PrimaryDns']
    secondary_dns_ip = d['SecondaryDns']

    print('  Connection status: ' + get_connection_status(connection_status))
    if connection_status == '901':
        print('    Network type: ' + get_network_type(network_type))
        print('    Signal level: ' + get_signal_level(signal_level), end="")
        if signal_strength is not None:
            print(' (' + signal_strength + '%)')
        else:
            print('')
        print('    Roaming: ' + get_roaming_status(roaming_status))
        print('    DNS IP addresses: ' + primary_dns_ip + ', ' + secondary_dns_ip)

    return connection_status

def print_device_info(session, device_ip, token):
    d = call_api(session, device_ip, token, '/api/device/information')
    #print(json.dumps(d, indent=4))
    device_name = d['DeviceName']
    serial_number = d['SerialNumber']
    imei = d['Imei']
    hardware_version = d['HardwareVersion']
    software_version = d['SoftwareVersion']
    webui_version = d['WebUIVersion']
    mac_address1 = d['MacAddress1']
    mac_address2 = d['MacAddress2']
    product_family = d['ProductFamily']
 
    print('Huawei ' + device_name + ' ' + product_family + ' Modem (IMEI: ' + imei + ')')
    print('  Hardware version: ' + hardware_version)
    print('  Software version: ' + software_version)
    print('  Web UI version: ' + webui_version)
    print('  Serial: ' + serial_number)
    print('  MAC address (modem): ' + mac_address1)
    if mac_address2 is not None:
        print('  MAC address (WiFi): ' + mac_address2)

def print_provider(session, device_ip, token, connection_status):
    if connection_status == '901':
        d = call_api(session, device_ip, token, '/api/net/current-plmn')
        #print(json.dumps(d, indent=4))
        provider_name = d['FullName']
        print('    Network operator: ' + provider_name)

def print_signal(session, device_ip, token, connection_status):
    if connection_status == '901':
        d = call_api(session, device_ip, token, '/api/device/signal')
        #print(json.dumps(d, indent=4))
        cell_id = d['cell_id']
        rsrq = d['rsrq']
        rsrp = d['rsrp']
        rssi = d['rssi']
        sinr = d['sinr']
        print('    Cell ID: ' + cell_id)
        print('    RSSI: ' + rssi)
        print('    RSRQ: ' + rsrq)
        print('    RSRP: ' + rsrp)
        print('    SINR: ' + sinr)

def print_unread(session, device_ip, token):
    d = call_api(session, device_ip, token, '/api/monitoring/check-notifications')
    unread_messages = d['UnreadMessage']
    print('  Unread SMS: ' + unread_messages)

device_ip = 'hi.link'
if len(sys.argv) == 2:
    device_ip = sys.argv[1]

if not is_hilink(device_ip):
    print("Can't find a Huawei HiLink device on " + device_ip)
    sys.exit(-1)

session = requests.Session()

me = login(session, device_ip)
#print("me=" + str(me))
if me is None:
    print("Can't login")
    sys.exit(-1)

session.cookies.set('SessionID', me['session'])
token = me['token']

print_device_info(session, device_ip, token)
connection_status = print_connection_status(session, device_ip, token)
print_signal(session, device_ip, token, connection_status)
print_provider(session, device_ip, token, connection_status)
print_traffic_statistics(session, device_ip, token, connection_status)
print_unread(session, device_ip, token)
