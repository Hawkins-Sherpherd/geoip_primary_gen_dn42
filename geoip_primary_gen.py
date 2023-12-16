import os
import csv
import re
import ipaddress

# Generate primary GeoIP data for NextTrace
# Author: Hawkins Sherpherd

CIDR_HEADER = "^cidr"
ROUTE_HEADER = "^route"
ROUTE6_HEADER = "^route6"
NETNAME_HEADER = "^netname"
COUNTRY_HEADER = "^country"
ORIGIN_HEADER = "^origin"
INET4_CIDR = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/(3[0-2]|2[0-9]|1[0-9]|[0-9]))?$'
INET6_CIDR = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/((1(1[0-9]|2[0-8]))|([0-9][0-9])|([0-9])))?$'

inet_data_path = "./data/inetnum/"
inet6_data_path = "./data/inet6num/"
route_data_path = "./data/route/"
route6_data_path = "./data/route6/"

def get_file_path(data_path):
    files_list = os.listdir(data_path)
    path_list = [None]*len(files_list)
    for i in range(len(files_list)):
        path_list[i] = data_path + files_list[i]
    return path_list

inetnum_files = get_file_path(inet_data_path)
inet6num_files = get_file_path(inet6_data_path)
route_files = get_file_path(route_data_path)
route6_files = get_file_path(route6_data_path)
geoip_files = "geoip_primary.csv"

try:
    geoip_primary_csv = open(geoip_files,"r")
    geoip_primary_csv.close()
except FileNotFoundError:
    print(geoip_files+" not exist, creating......")
    try:
        geoip_primary_csv = open(geoip_files,"w")
        geoip_primary_csv.close()
    except PermissionError:
        print(geoip_files+": Permission Denied")
        exit(1)
except PermissionError:
    print(geoip_files+": Permission Denied")
    exit(1)

def find_lines(header,file,pattern):
    result = pattern
    result_keys = list(result.keys())
    lines = file.readlines()
    filtered_items = []
    for i in range(len(result_keys)):
        filtered_lines = []
        for j in range(len(lines)):
            if re.search(header[i],lines[j]):
                filtered_lines.append(lines[j])
            else:
                continue
        filtered_items.append(filtered_lines)
    for i in range(len(result_keys)):
        result[result_keys[i]] = filtered_items[i]
    return result

def fetch_route(route_files):
    route = {}
    result_pattern = {'cidr':'','origin':''}
    regex_list = [ROUTE_HEADER,ORIGIN_HEADER]
    strip_list = ['route:              ','origin:             AS','\n']
    for i in range(len(route_files)):
        current_file = open(route_files[i],'r')
        result = find_lines(regex_list,current_file,result_pattern)
        for j in range(len(result['cidr'])):
            for k in strip_list:
                result['cidr'][j] = result['cidr'][j].strip(k)
        for j in range(len(result['origin'])):
            for k in strip_list:
                result['origin'][j] = result['origin'][j].strip(k)
        route[result['cidr'][0]] = [(result['origin'])]
    return route

def fetch_data(files,result_pattern,regex_list,strip_list):
    data = {}
    data_keys = list(result_pattern.keys())
    for i in range(len(files)):
        current_file = open(files[i],'r')
        result = find_lines(regex_list,current_file,result_pattern)
        data_list = []
        for j in range(len(data_keys)):
            for k in range(len(result[data_keys[j]])):
                for l in strip_list:
                    result[data_keys[j]][k] = result[data_keys[j]][k].strip(l)
        for j in range(1,len(data_keys)):
            data_list.append(result[data_keys[j]])
        data[result[data_keys[0]][0]] = data_list
    return data

def generate_geoip_list(inetnum,as_info):
    # Order: IP_CDIR,LtdCode,ISO3166-2,CityName,ASN,IPWhois(Netname)
    geoip_list = []
    supernet_keys = list(inetnum.keys())
    subnet_keys = list(as_info.keys())
    subnet_supernet_map_4 = {}
    subnet_supernet_map_6 = {}
    supernet4 = []
    supernet6 = []
    subnet4 = []
    subnet6 = []
    for i in range(len(supernet_keys)):
        if re.search(INET4_CIDR,supernet_keys[i]):
            supernet4.append(ipaddress.IPv4Network(supernet_keys[i]))
        else:
            supernet6.append(ipaddress.IPv6Network(supernet_keys[i]))
    for i in range(len(subnet_keys)):
        if re.search(INET4_CIDR,subnet_keys[i]):
            subnet4.append(ipaddress.IPv4Network(subnet_keys[i]))
        else:
            subnet6.append(ipaddress.IPv6Network(subnet_keys[i]))
    for i in range(len(subnet4)):
        subnet_supernet_map_4[str(subnet4[i])] = str()
        supernet_list = []
        for j in range(len(supernet4)):
            if subnet4[i].subnet_of(supernet4[j]):
                supernet_list.append(supernet4[j])
            else:
                continue
            most_specific = supernet_list[0]
            for k in range(len(supernet_list)):
                current = supernet_list[k]
                if current >= most_specific:
                    most_specific = current
                else:
                    continue
        subnet_supernet_map_4[str(subnet4[i])] = str(most_specific)
    for i in range(len(subnet6)):
        subnet_supernet_map_6[str(subnet6[i])] = str()
        supernet_list = []
        for j in range(len(supernet6)):
            if subnet6[i].subnet_of(supernet6[j]):
                supernet_list.append(supernet6[j])
            else:
                continue
            most_specific = supernet_list[0]
            for k in range(len(supernet_list)):
                current = supernet_list[k]
                if current >= most_specific:
                    most_specific = current
                else:
                    continue
        subnet_supernet_map_6[str(subnet6[i])] = str(most_specific)
    subnet_supernet_map = {**subnet_supernet_map_4,**subnet_supernet_map_6}
    # Construct geoip_list
    # Order: IP_CDIR,LtdCode,ISO3166-2,CityName,ASN,IPWhois(Netname)
    subnet_supernet_keys = list(subnet_supernet_map.keys())
    for i in range(len(subnet_supernet_keys)):
        line = ['','','','','','']
        line[0] = subnet_supernet_keys[i]
        line[1] = ','.join(inetnum[subnet_supernet_map[subnet_supernet_keys[i]]][0])
        line[2] = ''
        line[3] = ''
        line[4] = ','.join(routes[subnet_supernet_keys[i]][0])
        line[5] = ','.join(inetnums[subnet_supernet_map[subnet_supernet_keys[i]]][1])
        with open('debug_geoip_list_line','a') as debug:
            print(line,file=debug)
        geoip_list.append(line)
    return geoip_list

def export_csv(geoip_list):
    geoip_primary_csv = open(geoip_files,'w')
    writer = csv.writer(geoip_primary_csv, quoting=csv.QUOTE_ALL)
    for i in geoip_list:
        writer.writerow(i)
    geoip_primary_csv.close()
    return 0

result_pattern = {'cidr':'','origin':''}
regex_list = [ROUTE_HEADER,ORIGIN_HEADER]
strip_list = ['route:              ','origin:             AS','\n']
route4 = fetch_data(route_files,result_pattern,regex_list,strip_list)
regex_list = [ROUTE6_HEADER,ORIGIN_HEADER]
strip_list = ['route6:             ','origin:             AS','\n']
route6 = fetch_data(route6_files,result_pattern,regex_list,strip_list)
routes = {**route4,**route6}

result_pattern = {'cidr':'','country':'','netname':'',}
regex_list = [CIDR_HEADER,COUNTRY_HEADER,NETNAME_HEADER]
strip_list = ['cidr:               ','netname:            ','country:            ','\n']
inetnum4 = fetch_data(inetnum_files,result_pattern,regex_list,strip_list)
inetnum6 = fetch_data(inet6num_files,result_pattern,regex_list,strip_list)
del inetnum6['/0'] # It causes error and unnecessary
inetnums = {**inetnum4,**inetnum6}

export_csv(generate_geoip_list(inetnums,routes))