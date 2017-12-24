test:
	go test ./... -v -race

cover:
	rm -f *.coverprofile
	go test -coverprofile=csrf.coverprofile
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

.PHONY: test cover
