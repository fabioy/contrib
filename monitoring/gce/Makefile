all: push

TAG = 0.1
PREFIX = gcr.io/fabioy-cloud-test-1/resource_metrics

server: resource_metrics.go
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w' -o resource_metrics ./resource_metrics.go

container: server
	docker build -t $(PREFIX):$(TAG) .

push: container
	gcloud docker push $(PREFIX):$(TAG)

clean:
	rm -f resource_metrics
