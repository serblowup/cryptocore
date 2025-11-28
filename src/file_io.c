/*
 * file_io.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <stdio.h>
#include <stdlib.h>

int read_file(const char *filename, BYTE **data, size_t *data_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s' for reading\n", filename);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    *data_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (*data_len == 0) {
        *data = NULL;
        fclose(file);
        return 1;
    }

    *data = (BYTE*)malloc(*data_len);
    if (!*data) {
        fprintf(stderr, "Error: Memory allocation failed for file '%s'\n", filename);
        fclose(file);
        return 0;
    }

    size_t bytes_read = fread(*data, 1, *data_len, file);
    fclose(file);

    if (bytes_read != *data_len) {
        fprintf(stderr, "Error: Read %zu bytes from '%s', expected %zu\n", bytes_read, filename, *data_len);
        free(*data);
        *data = NULL;
        return 0;
    }

    return 1;
}

int write_file(const char *filename, const BYTE *data, size_t data_len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s' for writing\n", filename);
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, data_len, file);
    fclose(file);

    if (bytes_written != data_len) {
        fprintf(stderr, "Error: Wrote %zu bytes to '%s', expected %zu\n", bytes_written, filename, data_len);
        return 0;
    }

    return 1;
}

int process_file_in_chunks(const char *filename,
                          void (*process_chunk)(const BYTE *chunk, size_t chunk_len, void *context),
                          void *context,
                          size_t chunk_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s' for reading\n", filename);
        return 0;
    }

    BYTE *chunk = malloc(chunk_size);
    if (!chunk) {
        fprintf(stderr, "Error: Memory allocation failed for chunk buffer\n");
        fclose(file);
        return 0;
    }

    size_t total_bytes = 0;
    size_t bytes_read;

    while ((bytes_read = fread(chunk, 1, chunk_size, file)) > 0) {
        process_chunk(chunk, bytes_read, context);
        total_bytes += bytes_read;
    }

    free(chunk);
    fclose(file);

    printf("Processed %zu bytes from '%s' in chunks of %zu bytes\n",
           total_bytes, filename, chunk_size);
    return 1;
}

int get_file_size(const char *filename, size_t *file_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fclose(file);

    return 1;
}
