// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 Facebook
 */
#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "bpf_load.h"

#define MAX_CNT 1000000
#define DUMMY_IP "127.0.0.1"
#define DUMMY_PORT 80

static __u64 time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void test_task_rename(int cpu)
{
	char buf[] = "test\n";
	__u64 start_time;
	int i, fd;

	fd = open("/proc/self/comm", O_WRONLY|O_TRUNC);
	if (fd < 0) {
		printf("couldn't open /proc\n");
		exit(1);
	}
	start_time = time_get_ns();
	for (i = 0; i < MAX_CNT; i++) {
		if (write(fd, buf, sizeof(buf)) < 0) {
			printf("task rename failed: %s\n", strerror(errno));
			close(fd);
			return;
		}
	}
	printf("task_rename:%d: %lld events per sec\n",
	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
	close(fd);
}

static void test_fib_table_lookup(int cpu)
{
	struct sockaddr_in addr;
	char buf[] = "test\n";
	__u64 start_time;
	int i, fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		printf("couldn't open socket\n");
		exit(1);
	}
	memset((char *)&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = inet_addr(DUMMY_IP);
	addr.sin_port = htons(DUMMY_PORT);
	addr.sin_family = AF_INET;
	start_time = time_get_ns();
	for (i = 0; i < MAX_CNT; i++) {
		if (sendto(fd, buf, strlen(buf), 0,
			   (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			printf("failed to start ping: %s\n", strerror(errno));
			close(fd);
			return;
		}
	}
	printf("fib_table_lookup:%d: %lld events per sec\n",
	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
	close(fd);
}

static void loop(int cpu, int flags)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);

	if (flags & 1)
		test_task_rename(cpu);
	if (flags & 2)
		test_fib_table_lookup(cpu);
}

static void run_perf_test(int tasks, int flags)
{
	pid_t pid[tasks];
	int i;

	for (i = 0; i < tasks; i++) {
		pid[i] = fork();
		if (pid[i] == 0) {
			loop(i, flags);
			exit(0);
		} else if (pid[i] == -1) {
			printf("couldn't spawn #%d process\n", i);
			exit(1);
		}
	}
	for (i = 0; i < tasks; i++) {
		int status;

		assert(waitpid(pid[i], &status, 0) == pid[i]);
		assert(status == 0);
	}
}

static void unload_progs(void)
{
	close(prog_fd[0]);
	close(prog_fd[1]);
	close(event_fd[0]);
	close(event_fd[1]);
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char filename[256];
	int num_cpu = 8;
	int test_flags = ~0;

	setrlimit(RLIMIT_MEMLOCK, &r);

	if (argc > 1)
		test_flags = atoi(argv[1]) ? : test_flags;
	if (argc > 2)
		num_cpu = atoi(argv[2]) ? : num_cpu;

	if (test_flags & 0x3) {
		printf("BASE\n");
		run_perf_test(num_cpu, test_flags);
	}

	if (test_flags & 0xC) {
		snprintf(filename, sizeof(filename),
			 "%s_kprobe_kern.o", argv[0]);
		if (load_bpf_file(filename)) {
			printf("%s", bpf_log_buf);
			return 1;
		}
		printf("w/KPROBE\n");
		run_perf_test(num_cpu, test_flags >> 2);
		unload_progs();
	}

	if (test_flags & 0x30) {
		snprintf(filename, sizeof(filename),
			 "%s_tp_kern.o", argv[0]);
		if (load_bpf_file(filename)) {
			printf("%s", bpf_log_buf);
			return 1;
		}
		printf("w/TRACEPOINT\n");
		run_perf_test(num_cpu, test_flags >> 4);
		unload_progs();
	}

	if (test_flags & 0xC0) {
		snprintf(filename, sizeof(filename),
			 "%s_raw_tp_kern.o", argv[0]);
		if (load_bpf_file(filename)) {
			printf("%s", bpf_log_buf);
			return 1;
		}
		printf("w/RAW_TRACEPOINT\n");
		run_perf_test(num_cpu, test_flags >> 6);
		unload_progs();
	}

	return 0;
}
