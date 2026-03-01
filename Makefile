ACT=act
JOB=build-scan-sign

.PHONY: act-curl act-all

act-curl:
	DOCKER_HOST=unix://$(HOME)/.colima/default/docker.sock \
	$(ACT) push -j $(JOB) --matrix tool:curl

act-all:
	DOCKER_HOST=unix://$(HOME)/.colima/default/docker.sock \
	$(ACT) push -j $(JOB)
