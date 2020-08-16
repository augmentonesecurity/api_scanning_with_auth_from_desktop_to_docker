#!/bin/bash
#
# Run  Docker image of zap 
IMAGE="owasp/zap2docker-stable"
ROOTPATH=~/api_scanning_with_auth_from_desktop_to_docker/mounted_dir
API_DEF_URL=http://127.0.0.1:8084/v2/api-docs
REPORTNAME=testreport.html
CONTEXT_FILE=/zap/wrk/Authorization_Code_Flow.context

# Ensure that mounted_dir is readable and writeable inside docker. 
chmod 775 ${ROOTPATH}

# make sure that all files are executable before they are copied into the docker container or else you will not be able to execute the modified zap_common.py
find ${ROOTPATH} -type f -exec chmod 777 {} +

docker pull ${IMAGE}

# starting up the container, note that we need to specify the --network="host" flag so that docker knows that when we use 127.0.0.1
# we are pointing to the host machine. This is how we connect to the authorization and resource servers.
sudo docker run -d --network="host" --name=zap_container -v ${ROOTPATH}:/zap/wrk/:rw -t ${IMAGE}

# we copy all the modified files into docker, Zap has not started yet, it will be started by zap-api-scan.py
docker cp ${ROOTPATH}/config.xml $(docker inspect --format="{{.Id}}" zap_container):/zap/xml
docker cp ${ROOTPATH}/log4j.properties $(docker inspect --format="{{.Id}}" zap_container):/zap/xml
docker cp ${ROOTPATH}/zap-api-scan.py $(docker inspect --format="{{.Id}}" zap_container):/zap/zap-api-scan.py
docker cp ${ROOTPATH}/zap_common.py $(docker inspect --format="{{.Id}}" zap_container):/zap/zap_common.py

# now we execute the api scan, note that we also had to include the jython addon, which is the python scripting addon 
# as it is not installed by default
docker exec -t $(docker inspect --format="{{.Id}}" zap_container) /zap/zap-api-scan.py \
	-t ${API_DEF_URL} \
	-f openapi \
	-r ${REPORTNAME} \
	-n ${CONTEXT_FILE} \
	-z "-addoninstall jython" \
	-d
	
# we copy the log file into the mounted directory for further investigation if need be	
# note that if you use weekly images, the home directory is /home/zap/.ZAP_D
docker cp $(docker inspect --format="{{.Id}}" zap_container):/home/zap/.ZAP/zap.log ${ROOTPATH}

# stopping and removing the container
docker container stop $(docker inspect --format="{{.Id}}" zap_container) 
docker container rm $(docker inspect --format="{{.Id}}" zap_container)
