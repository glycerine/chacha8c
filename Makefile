compare:
	go run ./chacha8rand.go > go.out
	gcc chacha8.c && ./a.out > c.out
	diff c.out go.out && rm a.out
