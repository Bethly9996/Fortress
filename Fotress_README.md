**BUILDING FORTRESS**

Prerequisites

    A Linux server running Ubuntu 20.04 LTS
    Root access to the server
    Basic knowledge of Linux terminal commands


__Integrating Wazuh, Elastic Search, Filebeat, and Kibana__

This guide provides instructions to integrate Wazuh, Elastic Search, Filebeat, and Kibana components in a single all-in-one deployment. It covers the installation and configuration of these components on a Linux machine.

Note: You need root user privileges to run all the commands described below.

Prerequisites

Ensure the following packages are installed on the server:
	apt-get install apt-transport-https zip unzip lsb-release curl gnupg
	
	
**INSTALLATION OF ELASTICSEARCH**
Elastic Search is a search engine that stores data in a distributed manner, allowing for easy search and analysis. Follow the steps below to install Elastic Search:

Elasticsearch is a scalable full-text search and analytics engine.

  1. Add the Elastic Stack repository:
    	
	curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/elasticsearch.gpg --import
	&& chmod 644 /usr/share/keyrings/elasticsearch.gpg
	echo "deb [signed-by=/usr/share/keyrings/elasticsearch.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d 
	apt-get update

 2. apt-get install elasticsearch=7.17.9
 	apt-get install elasticsearch=7.17.9
 	
 3. Download the Elasticsearch configuration file:
 	mkdir /etc/elasticsearch/certs/ca -p
 	
 4. Download the configuration file for creating the certificates:
 	curl -so /usr/share/elasticsearch/instances.yml https://packages.wazuh.com/4.4/tpl/elastic-basic/instances_aio.yml
 	
 5. Create the certificates using the elasticsearch-certutil tool:
 	/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip
 	
 6. Extract the generated /usr/share/elasticsearch/certs.zip file: 
 	unzip ~/certs.zip -d ~/certs
 	
 7. Copy the CA file, the certificate, and the key to /etc/elasticsearch/certs:
 	cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/
 	
 8. Set the owner and permissions:
 	chown -R elasticsearch: /etc/elasticsearch/certs
	chmod -R 500 /etc/elasticsearch/certs
	chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.*
	rm -rf ~/certs/ ~/certs.zip
	
 9. Enable and start the Elasticsearch service:
 	systemctl daemon-reload
	systemctl enable elasticsearch
	systemctl start elasticsearch
	
10. Generate credentials for all the Elastic Stack pre-built roles and users:
    	/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
    	
11. Save the password of the elastic user for future steps.
	Output:
	Changed password for user apm_system
	PASSWORD apm_system = lLPZhZkB6oUOzzCrkLSF

	Changed password for user kibana_system
	PASSWORD kibana_system = TaLqVOnSoqKTYLIU0vDn

	Changed password for user kibana
	PASSWORD kibana = TaLqVOvXoqKTYLIU0vDn

	Changed password for user logstash_system

12. To check that the installation was made successfully, run the following command replacing <elastic_password> with the password generated in the previous step for elastic user:
	curl -XGET https://localhost:9200 -u elastic:<elastic_password> -k

13. If the installation was successful, you should see output similar to the following:
	{
  	"name" : "ubuntu",
  	"cluster_name" : "elasticsearch",
  	"cluster_uuid" : "fnq3Zj6HRd-yPzZJ8pOg1A",
  	"version" : {
    	"number" : "7.12.0",
    	"build_flavor" : "default",
    	"build_type" : "deb",
    	"build_hash" : "78722783c38caa25a70982b5b042074cde5d3b3a",
    	"build_date" : "2021-03-18T06:17:15.410153305Z",
    	"build_snapshot" : false,
    	"lucene_version" : "8.8.0",
    	"minimum_wire_compatibility_version" : "6.8.0",
    	"minimum_index_compatibility_version" : "6.0.0-beta1"
  	},
 	 "tagline" : "You Know, for Search"
	}
	
.............................................................................................................................................................................	..

**WAZUH INSTALLATION**

Wazuh is an open-source security monitoring solution that helps you detect and respond to security threats in real-time. 

Follow the steps below to install Wazuh:

1. Add the Wazuh repository to the server:
 	curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
 	echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
 	sudo apt-get update
 	
2. Install the Wazuh manager package:
	sudo apt-get install wazuh-manager
	
3. Enable and start the Wazuh manager service:
	sudo systemctl daemon-reload
	sudo systemctl enable wazuh-manager
	sudo systemctl start wazuh-manager
	
4. To verify that the Wazuh manager is running, run the following command:
	 systemctl status wazuh-manager

...........................................................................................................................................................................
**INSTALLING FILEBEAT**

Filebeat is a tool on the Wazuh server that securely forwards alerts and archived events to Elasticsearch.

   1. Install the Filebeat package:
    	apt-get install filebeat=7.17.9

   2. Download the pre-configured Filebeat config file used to forward Wazuh alerts to Elasticsearch:
   	curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.4/tpl/elastic-basic/filebeat_all_in_one.yml

   3. Download the alerts template for Elasticsearch:
	curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.4/extensions/elasticsearch/7.x/wazuh-template.json 
	chmod go+r /etc/filebeat/wazuh-template.json
   4. Download the Wazuh module for Filebeat:
   	curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.2.tar.gz | tar -xvz -C /usr/share/filebeat/module
   	
   5. Edit the file /etc/filebeat/filebeat.yml and add the following line:
   	output.elasticsearch.password: <elasticsearch_password>

        Replace <elasticsearch_password> with the previously generated password for the elastic user.
   6. Copy the certificates into /etc/filebeat/certs/
   	cp -r /etc/elasticsearch/certs/ca/ /etc/filebeat/certs/
	cp /etc/elasticsearch/certs/elasticsearch.crt /etc/filebeat/certs/filebeat.crt
	cp /etc/elasticsearch/certs/elasticsearch.key /etc/filebeat/certs/filebeat.keY
	
   7. Enable and start the Filebeat service:
   	systemctl daemon-reload
	systemctl enable filebeat
	systemctl start filebeat
	
   8. To ensure that Filebeat has been successfully installed, run the following command:
   	filebeat test output
	
	This command should have an output similar to the following:
	elasticsearch: https://127.0.0.1:9200...
  		parse url... OK
 		 connection...
    		parse host... OK
    		dns lookup... OK
    		addresses: 127.0.0.1
    		dial up... OK
  	TLS...
    		security: server's certificate chain verification is enabled
    		handshake... OK
    		TLS version: TLSv1.3
    		dial up... OK
  	talk to server... OK
  	version: 7.17.9
  	
 .............................................................................................................................................................................
 **INSTALLING KIBANA**
Kibana is a flexible and intuitive web interface for mining and visualizing the events and archives stored in Elasticsearch.

   1. Install the Kibana package:
   	apt-get install kibana=7.17.9

   2. Copy the Elasticsearch certificates into the Kibana configuration folder:
	mkdir /etc/kibana/certs/ca -p
	cp -R /etc/elasticsearch/certs/ca/ /etc/kibana/certs/
	cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key
	cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt
	chown -R kibana:kibana /etc/kibana/
	chmod -R 500 /etc/kibana/certs
	chmod 440 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*-

   3. Download the Kibana configuration file:
   	curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/4.4/tpl/elastic-basic/kibana_all_in_one.yml

   4. Edit the /etc/kibana/kibana.yml file:

    elasticsearch.password: <elasticsearch_password>
    Values to be replaced: <elasticsearch_password>: the password generated during the Elasticsearch installation and
    configuration for the elastic user.
    
   5. Create the /usr/share/kibana/data directory:
         mkdir /usr/share/kibana/data
         chown -R kibana:kibana /usr/share/kibana

   6. Install the Wazuh Kibana plugin. The installation of the plugin must be done from the Kibana home directory as follows:
	cd /usr/share/kibana
	sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.4.1_7.17.9-1.zip

   7. Link Kibana's socket to privileged port 443:
  	  setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node

   8. Enable and start the Kibana service:
  	systemctl daemon-reload
  	systemctl enable kibana
  	systemctl start kibana
...................................................................................................................................................................................................  	
**ACCESS THE WEB INTERFACE WAZAUH SERVER AND DASHBOARD**

  	URL: https://<wazuh_server_ip>
        user: elastic
        password: <PASSWORD_elastic>the password generated during the Elasticsearch installation process
		
	__Finally, Disable repositories__

	It is recommended to disable the Wazuh and Elastic Stack repositories to prevent unintentional updates that could potentially cause compatibility 	issues.
	To do so, run the following commands:
		sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
		sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/elastic-7.x.list
		apt-get update

..........................................................................................................................................................................

**INTEGRATING SURICATA WITH WAZUH FOR NETWORK INTRUSION DETECTION**
This guide will help you configure Suricata on an Ubuntu endpoint and integrate it with the Wazuh server for enhanced network intrusion detection. Suricata is a network-based intrusion detection system (NIDS) that monitors network traffic to provide additional security insights. Wazuh can then analyze these logs generated by Suricata for better threat detection.

1. Install Suricata on the Ubuntu endpoint:
			sudo add-apt-repository ppa:oisf/suricata-stable
			sudo apt-get update
			sudo apt-get install suricata -y
		Note: This guide tested the configuration process with version 6.0.8 of Suricata.

2. Download and extract the Emerging Threats Suricata ruleset:
	cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
	sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
	sudo chmod 640 /etc/suricata/rules/*.rules
3. Modify Suricata settings in the /etc/suricata/suricata.yaml file:

	HOME_NET: "<UBUNTU_IP>"
	EXTERNAL_NET: "any"

	default-rule-path: /etc/suricata/rules
	rule-files:
	- "*.rules"

     # Global stats configuration
	stats:
	enabled: no

     # Linux high speed capture support
       af-packet:
  	- interface: enp0s3

	Note: Replace "<UBUNTU_IP>" with the IP address of your Ubuntu endpoint.

4. Restart the Suricata service:
	sudo systemctl restart suricata

5. Configure the Wazuh agent to read the Suricata logs file by adding the following configuration to the /var/ossec/etc/ossec.conf file:

<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>

6. Restart the Wazuh agent to apply the changes:
	sudo systemctl restart wazuh-agent
	Note: Ensure that the Wazuh agent is installed and running on the Ubuntu endpoint before proceeding with this configuration.

......................................................................................................................................................................

   **FORTRESS**
     **STAYING AHEAD**
 ......................................................................................................






























