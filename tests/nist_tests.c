#include "../include/main.h"
#include <stdio.h>
#include <stdlib.h>

int generate_nist_test_file(const char* filename, size_t size_bytes) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Cannot create test file %s\n", filename);
        return 0;
    }

    uint8_t buffer[4096];
    size_t bytes_written = 0;
    int ret = 1;

    printf("NIST Test File Generation\n");
    printf("Generating %zu bytes for NIST tests...\n", size_bytes);

    while (bytes_written < size_bytes && ret == 1) {
        size_t chunk_size = (size_bytes - bytes_written < sizeof(buffer)) ?
                           size_bytes - bytes_written : sizeof(buffer);

        if (generate_random_bytes(buffer, chunk_size) != 1) {
            fprintf(stderr, "Error: Failed to generate random bytes\n");
            ret = 0;
            break;
        }

        if (fwrite(buffer, 1, chunk_size, file) != chunk_size) {
            fprintf(stderr, "Error: Write failed to test file\n");
            ret = 0;
            break;
        }

        bytes_written += chunk_size;

        if (size_bytes >= 1000000) {
            static int last_percent = -1;
            int percent = (bytes_written * 100) / size_bytes;
            if (percent != last_percent && percent % 10 == 0) {
                printf("Progress: %d%%\n", percent);
                last_percent = percent;
            }
        }
    }

    fclose(file);

    if (ret == 1) {
        printf("Success: Generated %zu bytes in '%s'\n", bytes_written, filename);
        printf("File ready for NIST STS testing\n");
    } else {
        fprintf(stderr, "Failed to generate NIST test file\n");
    }

    return ret;
}

void print_nist_instructions(void) {
    printf("\n NIST Test Instructions \n");
    printf("1) File 'nist_test_data.bin' has been generated\n");
    printf("2) Run NIST Statistical Test Suite\n");
    printf("3) View results in:\n");
    printf("   experiments/AlgorithmTesting/finalAnalysisReport.txt\n");
}


