compare:
	# a simple test comparing the Go, C, and C++ chacha8 output.
	go run ./go_src/chacha8rand.go > go.out
	gcc c_src/chacha8.c && ./a.out > c.out
	diff c.out go.out && rm a.out
	g++ -std=c++11 -Wall -Wextra -pedantic testcpp/main.cpp -o ./chacha8_testcpp
	./chacha8_testcpp > cpp.out
	diff cpp.out go.out && rm ./chacha8_testcpp
