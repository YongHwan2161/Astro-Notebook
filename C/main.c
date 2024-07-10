#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#define MAX_STARS 10000

typedef struct {
    char name[50];
    char ra[20];
    char dec[20];
    double mag;
} StarData;

void convert_bsc5_to_stardata(cJSON *bsc5_data, StarData *stardata, int *star_count) {
    int count = 0;
    cJSON *star;
    cJSON_ArrayForEach(star, bsc5_data) {
        cJSON *hr = cJSON_GetObjectItemCaseSensitive(star, "HR");
        cJSON *name = cJSON_GetObjectItemCaseSensitive(star, "N");
        cJSON *ra = cJSON_GetObjectItemCaseSensitive(star, "RA");
        cJSON *dec = cJSON_GetObjectItemCaseSensitive(star, "Dec");
        cJSON *v = cJSON_GetObjectItemCaseSensitive(star, "V");

        if (name && cJSON_IsString(name)) {
            strncpy(stardata[count].name, name->valuestring, sizeof(stardata[count].name) - 1);
        } else if (hr && cJSON_IsString(hr)) {
            snprintf(stardata[count].name, sizeof(stardata[count].name), "HR %s", hr->valuestring);
        } else {
            strcpy(stardata[count].name, "Unknown");
        }

        if (ra && cJSON_IsString(ra)) {
            strncpy(stardata[count].ra, ra->valuestring, sizeof(stardata[count].ra) - 1);
        } else {
            strcpy(stardata[count].ra, "");
        }

        if (dec && cJSON_IsString(dec)) {
            strncpy(stardata[count].dec, dec->valuestring, sizeof(stardata[count].dec) - 1);
        } else {
            strcpy(stardata[count].dec, "");
        }

        if (v && cJSON_IsString(v)) {
            stardata[count].mag = atof(v->valuestring);
        } else {
            stardata[count].mag = 0.0;
        }

        count++;
        if (count >= MAX_STARS) break;
    }

    *star_count = count;
}

int main() {
    FILE *file = fopen("/workspaces/Astro-Notebook/assets/json/bcs5-short.json", "r");
    if (file == NULL) {
        printf("Failed to open input file\n");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *json_string = (char *)malloc(file_size + 1);
    fread(json_string, 1, file_size, file);
    fclose(file);

    json_string[file_size] = '\0';

    cJSON *bsc5_data = cJSON_Parse(json_string);
    free(json_string);

    if (bsc5_data == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            printf("JSON parsing error: %s\n", error_ptr);
        }
        return 1;
    }

    StarData stardata[MAX_STARS];
    int star_count = 0;

    convert_bsc5_to_stardata(bsc5_data, stardata, &star_count);

    cJSON_Delete(bsc5_data);

    FILE *output = fopen("./assets/js/converted_stardata.js", "w");
    if (output == NULL) {
        printf("Failed to open output file\n");
        return 1;
    }

    fprintf(output, "const starData = [\n");
    for (int i = 0; i < star_count; i++) {
        fprintf(output, "  {\n");
        fprintf(output, "    \"name\": \"%s\",\n", stardata[i].name);
        fprintf(output, "    \"ra\": \"%s\",\n", stardata[i].ra);
        fprintf(output, "    \"dec\": \"%s\",\n", stardata[i].dec);
        fprintf(output, "    \"mag\": %.2f\n", stardata[i].mag);
        fprintf(output, "  }%s\n", (i < star_count - 1) ? "," : "");
    }
    fprintf(output, "];\n");

    fclose(output);

    printf("Conversion complete. %d stars processed.\n", star_count);

    return 0;
}