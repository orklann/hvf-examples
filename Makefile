all:
	clang++ -std=c++11 -framework Hypervisor -o protect protect_mode.c
	clang++ -std=c++11 -framework Hypervisor -o real real_mode.c