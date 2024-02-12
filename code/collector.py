##!/usr/bin/env python3
import time
import requests
import decimal
import json
import os
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # type: ignore 

from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily
from prometheus_client import start_http_server

class NSXAppCollector(object):

    # Define a Rate Limit Value. NSX allows a maximum of 100 API calls per second. To combat this, every (default) 30 calls, a 1 second pause will be made
    APICALLS = 0
    RATELIMITER = 30
    RATELIMITING = True
    DEBUG = False

    if "NSX_DEBUGMODE" in os.environ:
        if os.environ['NSX_HOST'] == True:
            DEBUG = True

    def __init__(self):
        pass

    # Common GET-Call function to API
    def call_api_get (self, host, uri, apiuser, apipw, returnToken = False):
        
        # Rate Limiting function
        if self.APICALLS >= self.RATELIMITER and RATELIMITING == True:
            if DEBUG: print("Hit Ratelimiter Value. Waiting for NSX API Rate Limit to cool down.")
            time.sleep(1)
            self.APICALLS = 0
        self.APICALLS += 1

        url = "https://"+host+uri
        req = requests.get(url, auth=HTTPBasicAuth(apiuser, apipw), verify = False)
        
        if req.status_code != 200:
            print ("UNKNOWN ERROR: Can't connect to %s failed: %s" % (url, "error"))
        
        if DEBUG: print (req.json())

        return req.json ()

    # Common POST-Call function to API
    def call_api_post (self, host, uri, apiuser, apipw, payload):	
        if self.APICALLS >= self.RATELIMITER and RATELIMITING == True:            
            if DEBUG: print("Hit Ratelimiter Value. Waiting for NSX API Rate Limit to cool down.")
            time.sleep(1)
            self.APICALLS = 0
        self.APICALLS += 1

        url = "https://"+host+uri
        headers = {"Content-Type":"application/json"}
        req = requests.post (url, data = payload, headers = headers, auth = HTTPBasicAuth(apiuser, apipw), verify = False)
        
        if req.status_code != 200:
            print ("UNKNOWN ERROR: Can't connect to %s failed: %s" % (url, "error"))
        
        if DEBUG: print (req.json())

        return req.json ()    
    

    # Common Value rounding function
    def round_down(self, value, decimals): # type: ignore
        with decimal.localcontext() as ctx:
            d = decimal.Decimal(value) # type: ignore
            ctx.rounding = decimal.ROUND_DOWN
            return round(d, decimals)
        
    # Common function to divide a long array / list in defined length sets of values
    def divide_chunks(self, l, n):
        for i in range(0, len(l), n): 
            yield l[i:i + n]

    # Replace special characters in NSX provided metric names for prometheus
    def format_prometheus(self, text):      
        return text.replace("-","_").replace(".","_").replace("/","_").replace(" ","_")

    # Collection function     
    def collect(self):
        host=os.environ['NSX_HOST']
        username=os.environ['NSX_USER']
        password=os.environ['NSX_PASS']

        if DEBUG: print ("Starting Collection for "+host)

        # Scraping EdgeNodes

        key_definition = self.call_api_get(host,"/napp/api/v1/metrics/key-info?resource_type="+"PolicyEdgeNode",username,password)["results"] # type: ignore

        keyarray = []
        for key in key_definition:
            keyarray.append(key["key"])

        response = self.call_api_get(host,"/api/v1/transport-nodes?node_types=EdgeNode",username,password)
        nodeobjects = []
        for node in response["results"]: 
            nodeobjects.append(node["id"])
        
        keychunks = list(self.divide_chunks(keyarray, 5))

        for chunk in keychunks:
            payload = {}
            payload["granularity"] = "FIVE_MINUTES"
            payload["max_num_data_points"] = 1
            payload["keys"] = chunk
            payload["resource_ids"] = nodeobjects
            payload["resource_type"] = "PolicyEdgeNode"

            result = self.call_api_post(host,"/napp/api/v1/metrics/data",username,password,json.dumps(payload))["results"]
            

            for noderesult in result:
                for keyresult in noderesult["key_results"]:  
                    for singlekeyresult in keyresult["results"]:
                        g = GaugeMetricFamily("nsx_edge_"+self.format_prometheus(keyresult["key"])+"_"+self.format_prometheus(singlekeyresult["object_id"]), keyresult["description"], labels=["resourcename","resourcetype","nodeid"])
                        g.add_metric(["nappmetrics_"+self.format_prometheus(singlekeyresult["node_name"]),"EdgeNode",self.format_prometheus(singlekeyresult["node_name"])], float(float(singlekeyresult["data"][0]["value"])))
                        print(g)
                        yield g    
          
        # Scraping Tier0Interfaces

        key_definition = self.call_api_get(host,"/napp/api/v1/metrics/key-info?resource_type="+"Tier0Interface",username,password)["results"] # type: ignore

        keyarray = []
        for key in key_definition:
            keyarray.append(key["key"])

        nodelist = self.call_api_get(host,"/policy/api/v1/infra/tier-0s/",username,password)
        gatewaylist = []
        for node in nodelist["results"]: 
            gatewayobject = {}
            gatewayobject["id"]=node["id"]
            gatewayobject["display_name"]=node["display_name"]
            gatewaylist.append(gatewayobject)
        
        interfacenames = {}
        interfacegatewaynames = {}
        nodeobjects = []
        for gateway in gatewaylist:
            services = self.call_api_get(host,"/policy/api/v1/infra/tier-0s/"+str(gateway["id"])+"/locale-services/",username,password)
            for service in services["results"]:
                interfacelist = self.call_api_get(host,"/policy/api/v1/infra/tier-0s/"+str(gateway["id"])+"/locale-services/"+service["id"]+"/interfaces",username,password)
                for interfaceresponse in interfacelist["results"]:
                    interfacenames[str(interfaceresponse["unique_id"])] = interfaceresponse["display_name"]
                    interfacegatewaynames[str(interfaceresponse["unique_id"])] = gateway["display_name"]
                    nodeobjects.append(interfaceresponse["unique_id"])

        keychunks = list(self.divide_chunks(keyarray, 5))

        for chunk in keychunks:
            payload = {}
            payload["granularity"] = "FIVE_MINUTES"
            payload["max_num_data_points"] = 1
            payload["keys"] = chunk
            payload["resource_ids"] = nodeobjects
            payload["resource_type"] = "Tier0Interface"

            result = self.call_api_post(host,"/napp/api/v1/metrics/data",username,password,json.dumps(payload))["results"]

            for noderesult in result:
                for keyresult in noderesult["key_results"]:  
                    for singlekeyresult in keyresult["results"]:
                        print(str(noderesult))
                        print(str(keyresult))
                        print(str(interfacenames[str(noderesult["resource_id"])]))
                        nodedisplayname = str(interfacenames[str(noderesult["resource_id"])])
                        gatewaydisplayname = str(interfacegatewaynames[str(noderesult["resource_id"])])
                           
                        g = GaugeMetricFamily("nsx_tier0int_"+self.format_prometheus(keyresult["key"]), keyresult["description"], labels=["resourcename","resourcetype","edgenode","referringobject","uplinkname","gatewayname"])
                        g.add_metric(["nappmetrics_"+self.format_prometheus(nodedisplayname)+"_"+self.format_prometheus(singlekeyresult["node_name"]),"tier0interface",self.format_prometheus(singlekeyresult["node_name"]),self.format_prometheus(singlekeyresult["object_id"]),self.format_prometheus(nodedisplayname),self.format_prometheus(gatewaydisplayname)], float(float(singlekeyresult["data"][0]["value"])))
                        yield g   

        # Scraping Tier1Gateway

        key_definition = self.call_api_get(host,"/napp/api/v1/metrics/key-info?resource_type="+"Tier1",username,password)["results"] # type: ignore

        keyarray = []
        for key in key_definition:
            keyarray.append(key["key"])

        nodelist = self.call_api_get(host,"/policy/api/v1/infra/tier-1s/",username,password)
        nodeobjects = []
        for node in nodelist["results"]: 
            nodeobjects.append(node["unique_id"])
        
        keychunks = list(self.divide_chunks(keyarray, 5))

        for chunk in keychunks:
            payload = {}
            payload["granularity"] = "FIVE_MINUTES"
            payload["max_num_data_points"] = 1
            payload["keys"] = chunk
            payload["resource_ids"] = nodeobjects
            payload["resource_type"] = "Tier1"

            result = self.call_api_post(host,"/napp/api/v1/metrics/data",username,password,json.dumps(payload))["results"]

            for noderesult in result:
                for keyresult in noderesult["key_results"]:  
                    for singlekeyresult in keyresult["results"]:
                        nodedisplayname = "UNDETERMINED"
                        for node in nodelist["results"]:
                            if node["unique_id"] == noderesult["resource_id"]:
                                nodedisplayname = node["display_name"]       

                        g = GaugeMetricFamily("nsx_tier1_"+self.format_prometheus(keyresult["key"]), keyresult["description"], labels=["resourcename","resourcetype","edgenode","referringobject","tier1gwname"])
                        g.add_metric(["nappmetrics_"+self.format_prometheus(nodedisplayname)+"_"+self.format_prometheus(singlekeyresult["node_name"]),"tier1",self.format_prometheus(singlekeyresult["node_name"]),self.format_prometheus(singlekeyresult["object_id"]),self.format_prometheus(nodedisplayname)], float(float(singlekeyresult["data"][0]["value"])))
                        yield g    

        # Scraping Tier0Gateway

        key_definition = self.call_api_get(host,"/napp/api/v1/metrics/key-info?resource_type="+"Tier0",username,password)["results"] # type: ignore

        keyarray = []
        for key in key_definition:
            keyarray.append(key["key"])

        nodelist = self.call_api_get(host,"/policy/api/v1/infra/tier-0s/",username,password)
        nodeobjects = []
        for node in nodelist["results"]: 
            nodeobjects.append(node["unique_id"])
        
        keychunks = list(self.divide_chunks(keyarray, 5))

        for chunk in keychunks:
            payload = {}
            payload["granularity"] = "FIVE_MINUTES"
            payload["max_num_data_points"] = 1
            payload["keys"] = chunk
            payload["resource_ids"] = nodeobjects
            payload["resource_type"] = "Tier0"

            result = self.call_api_post(host,"/napp/api/v1/metrics/data",username,password,json.dumps(payload))["results"]

            for noderesult in result:
                for keyresult in noderesult["key_results"]:  
                    for singlekeyresult in keyresult["results"]:
                        nodedisplayname = "UNDETERMINED"
                        for node in nodelist["results"]:
                            if node["unique_id"] == noderesult["resource_id"]:
                                nodedisplayname = node["display_name"]       

                        g = GaugeMetricFamily("nsx_tier0_"+self.format_prometheus(keyresult["key"]), keyresult["description"], labels=["resourcename","resourcetype","edgenode","referringobject","tier0gwname"])
                        g.add_metric(["nappmetrics_"+self.format_prometheus(nodedisplayname)+"_"+self.format_prometheus(singlekeyresult["node_name"]),"tier0",self.format_prometheus(singlekeyresult["node_name"]),self.format_prometheus(singlekeyresult["object_id"]),self.format_prometheus(nodedisplayname)], float(float(singlekeyresult["data"][0]["value"])))
                        yield g  

if __name__ == '__main__':
    start_http_server(8125)
    REGISTRY.register(NSXAppCollector()) # type: ignore
    while True:
        time.sleep(60)
