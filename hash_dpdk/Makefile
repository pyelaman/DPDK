APP = alkira_cxp_transit

SRCS-y := driver.c alkira_state_table.c alkira_gc.c dpdk_worker_pipeline.c dpdk_clamper.c dpdk_director.c dpdk_lb.c tcp_state_tracker.c

PKGCONF ?= pkg-config

CFLAGS += -O3 -Wall -Wextra $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)

all: $(APP)

$(APP): $(SRCS-y) alkira_state.h alkira_dpdk.h
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)

clean:
	rm -f $(APP)

