import whois
import dns.resolver
import shodan
import requests
import argparse
import socket
import json

argparse = argparse.ArgumentParser(description="This is a Information gathering tool.", usage="python3 info_gath.py -d DOMAIN [-s SHODAN]")
argparse.add_argument("-d", "--domain", help="Enter Domain Name for frootprinting.")
argparse.add_argument("-s", "--shodan", help="Enter The IP for shodan search.")
argparse.add_argument("-o", "--output", help="Enter The file name for save the output. ")


args = argparse.parse_args()

# which arguments you given to args that are copy to this domain and ip
domain = args.domain
ip = args.shodan
output = args.output

# print(f"[+] Domain {domain} and Ip {ip}  ")

print("\n[+]Getting whois information ...")

print("\n[+]]Whos is info found...")
py = whois.query(domain)
print(f"\nName : {py.name}")
print(f"Register : {py.registrar}")
print(f"Creation Date : {py.creation_date}")
print(f"expiration Date  : {py.expiration_date}")
#print(f"updated : {py.expiration_date}")

# Dns Module
print("\n[+] Getting DNS information ...")

try:
    for a in dns.resolver.resolve(domain, "A"):
        print("\n[+] A record :{}".format(a.to_text()))
    for mx in dns.resolver.resolve(domain, "MX"):
        print("[+] Mx record :{}".format(mx.to_text()))
    for ns in dns.resolver.resolve(domain, "NS"):
        print("[+] NS record :{}".format(ns.to_text()))
    for txt in dns.resolver.resolve(domain, "TXT"):
        print("[+] TXT record :{}".format(txt.to_text()))
    if output:
        with open (output,"a") as f:
            f.write("\n[+] Getting DNS information ...")
            f.write("\n[+] A record :{}".format(a.to_text()))
            f.write("\n[+] Mx record :{}".format(mx.to_text()))
            f.write("\n[+] TXT record :{}".format(txt.to_text()))
            f.write("\n[+] NS record :{}".format(ns.to_text()))
except:
    print("Dns Look is failed.")

# Geolocation module 
print("\nGetting inofrmaton form geolocation ....")
try :
    response = requests.request("Get", "http://geolocation-db.com/json/"+ socket.gethostbyname(domain)).json()
    print("\nCountry : {}".format(response["country_name"]) )
    print("City : {}".format(response["city"]))
    print("Psotal : {}".format(response["postal"]))
    print("Ipv4 : {}".format(response["IPv4"]))
    print("State: {}".format(response["state"]))

    if output:
        with open (output,"a") as f:
            f.write("\nGetting inofrmaton form geolocation ....")
            f.write("\nCountry : {}".format(response["country_name"]))
            f.write("\nCity : {}".format(response["city"]))
            f.write("\nPsotal : {}".format(response["postal"]))
            f.write("\nIpv4 : {}".format(response["IPv4"]))
            f.write("\nState: {}".format(response["state"]))


except:
    print("Error")

if ip :    
    
    # Getting shodan
    print(f"Getting info from shodan for ip {ip}")

    try :
        api = shodan.Shodan("P8vbZjgQX15vK24omNfVA6fmUwBmDWyx")
        ip2 = socket.gethostbyname(domain)
        results = api.search(ip2)

        print("[+] Results found : {}".format(results["total"]))
        for result in results["matches"]:
            print("[+] IP : {}".format(result['ip_str']))
            print("[+] Data : {}".format(result['data']))
            if output:
                with open (output,"a") as f:
                    f.write("\n[+] Getting DNS information ...")
                    f.write("\n[+] IP : {}".format(result['ip_str']))
                    f.write("\n[+] Data : {}".format(result['data']))
                   
    except:
        print("[-] No shodan information found.")
