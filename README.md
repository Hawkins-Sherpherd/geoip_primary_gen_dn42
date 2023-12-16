# geoip_primary_gen_dn42
Generate primary geoip data from dn42 registry for NextTrace

# How to use (Default)
* Put this into your dn42 registry folder
* Make dn42 registry your cwd
* python3 geoip_primary_gen.py
* It outputs geoip_primary.csv
* Do whatever you want to geoip_primary.csv, the data inside is ordered in this way per row:
  * IP_CDIR,LtdCode,ISO3166-2,CityName,ASN,IPWhois(Netname)
