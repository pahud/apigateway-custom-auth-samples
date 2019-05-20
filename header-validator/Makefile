APPNAME ?= main

.PHONY: deps
deps:
	go get -u ./...

.PHONY: clean
clean: 
	rm -rf ./src/main ./src/Gopkg.* ./src/vendor .cache
	
	GOOS=linux GOARCH=amd64 go build -o hello-world/hello-world ./hello-world

.PHONY: build
build:
ifeq ($(GOOS),darwin)
	@docker run -ti --rm \
	-v $(shell pwd)/src:/go/src/myapp.github.com \
	-v $(shell pwd)/Makefile:/go/src/myapp.github.com/Makefile \
	-w /go/src/myapp.github.com  golang:1.12 /bin/sh -c "make build-darwin"
else
	@docker run -ti --rm \
	-v $(shell pwd)/src:/go/src/myapp.github.com \
	-v $(shell pwd)/Makefile:/go/src/myapp.github.com/Makefile \
	-w /go/src/myapp.github.com  golang:1.12 /bin/sh -c "make build-linux"
endif


.PHONY: build-linux	
build-linux:
	@go get -u github.com/golang/dep/cmd/dep
	@[ ! -f ./Gopkg.toml ] && dep init || true
	@dep ensure
	@GOOS=linux GOARCH=amd64 go build -o $(APPNAME) main.go
	
.PHONY: sam-package
sam-package:
	@AWS_PROFILE=cn AWS_REGION=cn-north-1 sam package --s3-bucket=pahud-tmp-cn-north-1 > packaged.yaml
	
.PHONY: sam-deploy
sam-deploy:
	@AWS_PROFILE=cn AWS_REGION=cn-north-1 sam deploy --s3-bucket=pahud-tmp-cn-north-1 --template-file packaged.yaml \
	--stack-name ApigCustomAuthHeaderChk --capabilities CAPABILITY_IAM
	@AWS_PROFILE=cn AWS_REGION=cn-north-1 aws cloudformation describe-stacks --stack-name ApigCustomAuthHeaderChk --query 'Stacks[0].Outputs'

	
	