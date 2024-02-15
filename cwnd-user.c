#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
// #include <bpf/libbpf.h>
#include <uapi/linux/bpf.h>
// #include <bpf/bpf_helpers.h>

#define MAP_PATH "/sys/fs/bpf/wnd_map"

int main() {
    // struct bpf_object *obj;
    struct bpf_map *map;
    int map_fd;

    // Load the eBPF map from the filesystem
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Error loading eBPF map: %s\n", strerror(errno));
        return 1;
    }

    // Access the eBPF map
    map = bpf_map__next(NULL, map_fd);
    if (!map) {
        fprintf(stderr, "Error accessing eBPF map: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }

    // Read a value from the map
    uint32_t key = 0;  // Adjust the key based on your map's key type
    uint32_t value;
    int ret = bpf_map_lookup_elem(map_fd, &key, &value);
    if (ret) {
        fprintf(stderr, "Error reading value from eBPF map: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }

    printf("Value from the eBPF map: %llu\n", value);

    // Clean up
    close(map_fd);

    return 0;
}
