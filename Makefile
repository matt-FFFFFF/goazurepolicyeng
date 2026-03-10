TEST?=$$(go list ./... |grep -v 'vendor')

.PHONY: lint
lint:
	golangci-lint run

.PHONY: testrace
testrace:
	go test -test.v -race $(TEST)

.PHONY: test
test:
	go test -test.v $(TEST)

.PHONY: testcover
testcover:
	if [ -f "coverage.out" ]; then rm coverage.out; fi
	go test -coverprofile=coverage.out -covermode=count $(TEST)
