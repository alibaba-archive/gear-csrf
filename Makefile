test:
	go test ./... -v -race

cover:
	rm -f *.coverprofile
	go test -coverprofile=csrf.coverprofile
	go test -coverprofile=token.coverprofile ./token
	gover
	go tool cover -html=gover.coverprofile
	rm -f *.coverprofile

doc:
	godoc -http=:6060

.PHONY: test cover doc