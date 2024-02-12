#!/bin/bash

if [[ -z "${DOCKERREGISTRY}" ]]; then
  REPO="null"
  echo "Set Exporter Value with \"export DOCKERREGISTRY=value\""
else
  REPO="${DOCKERREGISTRY}"
  echo "Pushing to ${REPO}"
fi

docker build . -t nsxt-metrics-exporter
if [ "$REPO" != "null" ]; then
  docker tag nsxt-metrics-exporter "$REPO"
  docker push "$REPO"
fi