#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "tiny-json/tiny-json.h"

#ifdef _WIN32
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif

// Constants
#define VERSION "1.2"
#define REPOSITORY "https://github.com/offici5l/MiAssistantTool"
#define MAX_STR_LEN 80
#define RESPONSE_BUF_SIZE 4096
#define JSON_POOL_SIZE 10000
#define ADB_MAX_DATA (1024 * 1024)
#define ADB_SIDELOAD_CHUNK_SIZE (1024 * 64)
#define FILE_PATH_MAX 256
#define MD5_LEN 65

// ADB commands
#define ADB_CLASS 0xFF
#define ADB_SUB_CLASS 0x42
#define ADB_PROTOCOL_CODE 1
#define ADB_CONNECT 0x4E584E43
#define ADB_VERSION 0x01000001
#define ADB_OPEN 0x4E45504F
#define ADB_OKAY 0x59414B4F
#define ADB_WRTE 0x45545257
#define ADB_CLSE 0x45534C43
#define ADB_TRANSFER_DONE 0x00000000

// Data Structures
typedef struct {
    char device[MAX_STR_LEN];
    char version[MAX_STR_LEN];
    char sn[MAX_STR_LEN];
    char codebase[MAX_STR_LEN];
    char branch[MAX_STR_LEN];
    char language[MAX_STR_LEN];
    char region[MAX_STR_LEN];
    char romzone[MAX_STR_LEN];
} DeviceInfo;

typedef struct {
    uint32_t cmd;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t len;
    uint32_t checksum;
    uint32_t magic;
} AdbUsbPacket;

typedef struct {
    unsigned char key[16];
    unsigned char iv[16];
} CryptoConfig;

// Global USB context and device handle
static libusb_context *ctx = NULL;
static libusb_device_handle *dev_handle = NULL;
static int bulk_in = -1;
static int bulk_out = -1;
static int interface_num = -1;

// Global device info (for simplicity; could be passed as parameter)
static DeviceInfo global_device_info = {0};

// Crypto configuration
static const CryptoConfig crypto = {
    .key = {0x6D, 0x69, 0x75, 0x69, 0x6F, 0x74, 0x61, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x65, 0x64, 0x31, 0x31},
    .iv = {0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38}
};

// USB Communication Functions
int usb_read(void *data, int datalen, int *read_len) {
    if (!data || datalen <= 0 || !read_len) return -1;
    int r = libusb_bulk_transfer(dev_handle, bulk_in, data, datalen, read_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "USB read failed: %s\n", libusb_error_name(r));
        return -1;
    }
    return 0;
}

int usb_write(const void *data, int datalen, int *write_len) {
    if (!data || datalen <= 0 || !write_len) return -1;
    int r = libusb_bulk_transfer(dev_handle, bulk_out, (unsigned char*)data, datalen, write_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "USB write failed: %s\n", libusb_error_name(r));
        return -1;
    }
    return 0;
}

int send_command(uint32_t cmd, uint32_t arg0, uint32_t arg1, const void *data, int datalen) {
    AdbUsbPacket pkt = {
        .cmd = cmd,
        .arg0 = arg0,
        .arg1 = arg1,
        .len = datalen,
        .checksum = 0,
        .magic = cmd ^ 0xFFFFFFFF
    };

    int write_len;
    if (usb_write(&pkt, sizeof(pkt), &write_len) < 0 || write_len != sizeof(pkt)) {
        fprintf(stderr, "Failed to send ADB command packet\n");
        return -1;
    }

    if (datalen > 0 && data) {
        if (usb_write(data, datalen, &write_len) < 0 || write_len != datalen) {
            fprintf(stderr, "Failed to send ADB data\n");
            return -1;
        }
    }
    return 0;
}

int recv_packet(AdbUsbPacket *pkt, void *data, int *data_len) {
    if (!pkt || !data_len) return -1;

    int read_len;
    if (usb_read(pkt, sizeof(AdbUsbPacket), &read_len) < 0 || read_len != sizeof(AdbUsbPacket)) {
        fprintf(stderr, "Failed to read ADB packet\n");
        return -1;
    }

    *data_len = 0;
    if (pkt->len > 0 && data) {
        if (usb_read(data, pkt->len, &read_len) < 0 || read_len != (int)pkt->len) {
            fprintf(stderr, "Failed to read ADB data\n");
            return -1;
        }
        *data_len = read_len;
    }
    return 0;
}

char *adb_cmd(const char *command) {
    if (!command) return NULL;

    int cmd_len = strlen(command);
    if (send_command(ADB_OPEN, 1, 0, command, cmd_len + 1)) {
        fprintf(stderr, "Device rejected connect request for command: %s\n", command);
        return NULL;
    }

    AdbUsbPacket pkt;
    char dummy_data[512];
    int dummy_len;
    if (recv_packet(&pkt, dummy_data, &dummy_len)) {
        fprintf(stderr, "Failed to receive initial packet\n");
        return NULL;
    }

    char *response = malloc(RESPONSE_BUF_SIZE);
    if (!response) {
        fprintf(stderr, "Memory allocation failed for response\n");
        return NULL;
    }

    int data_len;
    if (recv_packet(&pkt, response, &data_len)) {
        fprintf(stderr, "Failed to receive response for command: %s\n", command);
        free(response);
        return NULL;
    }

    response[data_len] = '\0';
    if (data_len > 0 && response[data_len - 1] == '\n') {
        response[data_len - 1] = '\0';
    }

    // Consume any remaining packets
    if (recv_packet(&pkt, dummy_data, &dummy_len)) {
        fprintf(stderr, "Failed to receive final packet\n");
        free(response);
        return NULL;
    }

    return response;
}

// MD5 Calculation
int get_zip_file_path(char *file_path, size_t max_len) {
    while (1) {
        printf("Enter .zip file path: ");
        if (fgets(file_path, max_len, stdin)) {
            file_path[strcspn(file_path, "\n")] = '\0';
            if (strstr(file_path, ".zip")) {
                FILE *file = fopen(file_path, "rb");
                if (file) {
                    fclose(file);
                    return 0;
                }
            }
        }
        printf("Invalid file, try again.\n");
    }
}

int calculate_md5(const char *file_path, char *md5) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", file_path);
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        fprintf(stderr, "Failed to create MD5 context\n");
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Failed to initialize MD5 digest\n");
        return -1;
    }

    unsigned char data[1024];
    size_t bytes_read;
    while ((bytes_read = fread(data, 1, sizeof(data), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, data, bytes_read) != 1) {
            fclose(file);
            EVP_MD_CTX_free(mdctx);
            fprintf(stderr, "Failed to update MD5 digest\n");
            return -1;
        }
    }

    unsigned char md5_hash[EVP_MAX_MD_SIZE];
    unsigned int md5_len;
    if (EVP_DigestFinal_ex(mdctx, md5_hash, &md5_len) != 1) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Failed to finalize MD5 digest\n");
        return -1;
    }

    fclose(file);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < md5_len; i++) {
        sprintf(&md5[i * 2], "%02x", md5_hash[i]);
    }
    md5[md5_len * 2] = '\0';
    return 0;
}

// ROM Validation
int encrypt_data(const char *input, unsigned char *output, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create encryption context\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, crypto.key, crypto.iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Failed to initialize encryption\n");
        return -1;
    }

    int len = strlen(input);
    int mod_len = 16 - (len % 16);
    char padded[1024];
    memcpy(padded, input, len);
    if (mod_len > 0) memset(padded + len, mod_len, mod_len);
    len += mod_len;

    int update_len = 0, final_len = 0;
    if (EVP_EncryptUpdate(ctx, output, &update_len, (unsigned char*)padded, len) != 1 ||
        EVP_EncryptFinal_ex(ctx, output + update_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Encryption failed\n");
        return -1;
    }

    *out_len = update_len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

size_t write_callback(void *contents, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(contents, size, nmemb, stream);
}

int send_http_request(const char *encoded_data, char **response, size_t *response_size) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return -1;
    }

    char *escaped_data = curl_easy_escape(curl, encoded_data, strlen(encoded_data));
    if (!escaped_data) {
        curl_easy_cleanup(curl);
        fprintf(stderr, "Failed to escape data\n");
        return -1;
    }

    char post_buf[1024];
    snprintf(post_buf, sizeof(post_buf), "q=%s&t=&s=1", escaped_data);
    curl_free(escaped_data);

    FILE *response_file = fopen("response.tmp", "wb");
    if (!response_file) {
        curl_easy_cleanup(curl);
        fprintf(stderr, "Failed to open response file\n");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://update.miui.com/updates/miotaV3.php");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "MiTunes_UserAgent_v3.0");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_file);

    if (curl_easy_perform(curl) != CURLE_OK) {
        fclose(response_file);
        curl_easy_cleanup(curl);
        fprintf(stderr, "HTTP request failed\n");
        return -1;
    }
    fclose(response_file);
    curl_easy_cleanup(curl);

    response_file = fopen("response.tmp", "rb");
    if (!response_file) {
        fprintf(stderr, "Failed to read response file\n");
        return -1;
    }

    fseek(response_file, 0, SEEK_END);
    *response_size = ftell(response_file);
    fseek(response_file, 0, SEEK_SET);

    *response = malloc(*response_size + 1);
    if (!*response) {
        fclose(response_file);
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    fread(*response, 1, *response_size, response_file);
    (*response)[*response_size] = '\0';
    fclose(response_file);
    remove("response.tmp");
    return 0;
}

int decrypt_response(const char *input, size_t in_len, char *output, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create decryption context\n");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, crypto.key, crypto.iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Failed to initialize decryption\n");
        return -1;
    }

    int plain_len = 0, temp_len = 0;
    if (EVP_DecryptUpdate(ctx, (unsigned char*)output, &plain_len, (unsigned char*)input, in_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, (unsigned char*)output + plain_len, &temp_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Decryption failed\n");
        return -1;
    }

    *out_len = plain_len + temp_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

const char *validate_check(const char *md5, int flash) {
    char json_request[1024];
    snprintf(json_request, sizeof(json_request),
             "{\"d\":\"%s\",\"v\":\"%s\",\"c\":\"%s\",\"b\":\"%s\",\"sn\":\"%s\",\"l\":\"en-US\",\"f\":\"1\",\"options\":{\"zone\":%s},\"pkg\":\"%s\"}",
             global_device_info.device, global_device_info.version, global_device_info.codebase,
             global_device_info.branch, global_device_info.sn, global_device_info.romzone, md5);

    unsigned char enc_out[1024];
    int enc_out_len;
    if (encrypt_data(json_request, enc_out, &enc_out_len)) return NULL;

    char encoded_buf[EVP_ENCODE_LENGTH(enc_out_len)];
    EVP_EncodeBlock((unsigned char*)encoded_buf, enc_out, enc_out_len);

    char *response;
    size_t response_size;
    if (send_http_request(encoded_buf, &response, &response_size)) return NULL;

    unsigned char decoded_buf[1024];
    int decoded_len = EVP_DecodeBlock(decoded_buf, (unsigned char*)response, response_size);
    free(response);

    char decrypted_buf[1024];
    int decrypted_len;
    if (decrypt_response((char*)decoded_buf, decoded_len, decrypted_buf, &decrypted_len)) return NULL;

    char *json_start = strchr(decrypted_buf, '{');
    char *json_end = strrchr(decrypted_buf, '}');
    if (!json_start || !json_end) return NULL;

    size_t json_len = json_end - json_start + 1;
    char json_data[1024];
    memcpy(json_data, json_start, json_len);
    json_data[json_len] = '\0';

    json_t pool[JSON_POOL_SIZE];
    json_t const *parsed_json = json_create(json_data, pool, JSON_POOL_SIZE);
    if (!parsed_json) return NULL;

    if (flash) {
        json_t const *pkg_rom = json_getProperty(parsed_json, "PkgRom");
        if (pkg_rom) {
            int erase = atoi(json_getValue(json_getProperty(pkg_rom, "Erase")));
            if (erase) {
                printf("NOTICE: Data will be erased during flashing.\nPress Enter to continue...");
                getchar();
            }
            json_t const *validate = json_getProperty(pkg_rom, "Validate");
            return json_getValue(validate);
        } else {
            json_t const *code = json_getProperty(parsed_json, "Code");
            json_t const *message = json_getProperty(code, "message");
            printf("\n%s\n", json_getValue(message));
            return NULL;
        }
    } else {
        json_t const *child = json_getChild(parsed_json);
        if (child && (strcmp(json_getName(json_getSibling(child)), "Signup") == 0 ||
                      strcmp(json_getName(json_getSibling(child)), "VersionBoot") == 0)) {
            fprintf(stderr, "Error: Invalid data\n");
            return NULL;
        }
        while (child) {
            child = json_getSibling(child);
            if (strcmp(json_getName(child), "Icon") == 0) break;
            json_t const *cA = json_getProperty(parsed_json, json_getName(child));
            if (cA) {
                json_t const *md5_prop = json_getProperty(cA, "md5");
                if (md5_prop) {
                    printf("\n%s: %s\nmd5: %s\n", json_getName(child), json_getValue(json_getProperty(cA, "name")), json_getValue(md5_prop));
                }
            }
        }
        return NULL;
    }
}

// Sideloading
int start_sideload(const char *sideload_file, const char *validate) {
    FILE *fp = fopen(sideload_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file: %s\n", sideload_file);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char sideload_host_command[128];
    snprintf(sideload_host_command, sizeof(sideload_host_command),
             "sideload-host:%ld:%d:%s:0", file_size, ADB_SIDELOAD_CHUNK_SIZE, validate);

    if (send_command(ADB_OPEN, 1, 0, sideload_host_command, strlen(sideload_host_command) + 1)) {
        fclose(fp);
        fprintf(stderr, "Failed to send sideload command\n");
        return -1;
    }

    uint8_t *work_buffer = malloc(ADB_SIDELOAD_CHUNK_SIZE);
    if (!work_buffer) {
        fclose(fp);
        fprintf(stderr, "Failed to allocate work buffer\n");
        return -1;
    }

    char dummy_data[64];
    int dummy_data_size;
    AdbUsbPacket pkt;
    long total_sent = 0;

    while (1) {
        if (recv_packet(&pkt, dummy_data, &dummy_data_size)) {
            fprintf(stderr, "Failed to receive packet during sideload\n");
            break;
        }

        dummy_data[dummy_data_size] = '\0';
        if (dummy_data_size > 8) {
            printf("\n\n%s\n\n", dummy_data);
            break;
        }

        if (pkt.cmd == ADB_OKAY) {
            if (send_command(ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0)) {
                fprintf(stderr, "Failed to send OKAY response\n");
                break;
            }
        }

        if (pkt.cmd == ADB_TRANSFER_DONE && total_sent > 0) {
            continue;
        }

        if (pkt.cmd != ADB_WRTE) continue;

        long block = strtol(dummy_data, NULL, 10);
        long offset = block * ADB_SIDELOAD_CHUNK_SIZE;
        if (offset >= file_size) break;

        int to_write = ADB_SIDELOAD_CHUNK_SIZE;
        if (offset + ADB_SIDELOAD_CHUNK_SIZE > file_size) {
            to_write = file_size - offset;
        }

        fseek(fp, offset, SEEK_SET);
        if (fread(work_buffer, 1, to_write, fp) != (size_t)to_write) {
            fprintf(stderr, "Failed to read file chunk\n");
            break;
        }

        if (send_command(ADB_WRTE, pkt.arg1, pkt.arg0, work_buffer, to_write) ||
            send_command(ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0)) {
            fprintf(stderr, "Failed to send data or OKAY response\n");
            break;
        }

        total_sent += to_write;
        float progress = ((float)total_sent / file_size) * 100;
        printf("\rFlashing in progress ... %.1f%%", progress > 100 ? 100 : progress);
        fflush(stdout);
    }

    free(work_buffer);
    fclose(fp);
    printf("\n");
    return total_sent == file_size ? 0 : -1;
}

// Device Detection
int check_device(libusb_device *dev) {
    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != LIBUSB_SUCCESS) {
        fprintf(stderr, "Failed to get device descriptor\n");
        return -1;
    }

    struct libusb_config_descriptor *config;
    if (libusb_get_active_config_descriptor(dev, &config) != LIBUSB_SUCCESS) {
        fprintf(stderr, "Failed to get config descriptor\n");
        return -1;
    }

    bulk_in = -1;
    bulk_out = -1;
    interface_num = -1;

    for (int i = 0; i < config->bNumInterfaces; i++) {
        struct libusb_interface intf = config->interface[i];
        if (intf.num_altsetting == 0) continue;

        interface_num = i;
        struct libusb_interface_descriptor intf_desc = intf.altsetting[0];

        if (intf_desc.bInterfaceClass != ADB_CLASS ||
            intf_desc.bInterfaceSubClass != ADB_SUB_CLASS ||
            intf_desc.bInterfaceProtocol != ADB_PROTOCOL_CODE ||
            intf.num_altsetting != 1) {
            continue;
        }

        for (int j = 0; j < intf_desc.bNumEndpoints; j++) {
            struct libusb_endpoint_descriptor ep = intf_desc.endpoint[j];
            if ((ep.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK) continue;

            if ((ep.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
                bulk_out = ep.bEndpointAddress;
            } else {
                bulk_in = ep.bEndpointAddress;
            }

            if (bulk_in != -1 && bulk_out != -1) {
                libusb_free_config_descriptor(config);
                return 0;
            }
        }
    }

    libusb_free_config_descriptor(config);
    return -1;
}

// Main Program
void print_usage(const char *prog_name) {
    const char *choices[] = {"Read Info", "ROMs that can be flashed", "Flash Official Recovery ROM", "Format Data", "Reboot"};
    printf("\nVERSION: %s\nRepository: %s\n\nUsage: %s \033[0;32m<choice>\033[0m\n\n  \033[0;32mchoice\033[0m > description\n\n",
           VERSION, REPOSITORY, prog_name);
    for (int i = 0; i < 5; i++) {
        printf("  \033[0;32m%d\033[0m > %s\n\n", i + 1, choices[i]);
    }
}

int initialize_usb(int method, const char *fd) {
    if (libusb_init(&ctx) != LIBUSB_SUCCESS) {
        fprintf(stderr, "Failed to initialize libusb\n");
        return -1;
    }

    if (method == 1) { // Termux without root
        if (!fd) {
            fprintf(stderr, "TERMUX_USB_FD not set\n");
            return -1;
        }
        libusb_set_option(ctx, LIBUSB_OPTION_NO_DEVICE_DISCOVERY, NULL);
        if (libusb_wrap_sys_device(ctx, (intptr_t)atoi(fd), &dev_handle) != LIBUSB_SUCCESS) {
            fprintf(stderr, "Failed to wrap USB device\n");
            return -1;
        }
        if (check_device(libusb_get_device(dev_handle))) {
            fprintf(stderr, "Device not in Mi Assistant mode\n");
            return -1;
        }
    } else { // Windows or Linux with root
        libusb_device **devs;
        ssize_t cnt = libusb_get_device_list(ctx, &devs);
        if (cnt < 0) {
            fprintf(stderr, "Failed to get device list\n");
            return -1;
        }

        libusb_device *dev = NULL;
        for (ssize_t i = 0; i < cnt; i++) {
            if (check_device(devs[i]) == 0) {
                dev = devs[i];
                break;
            }
        }

        libusb_free_device_list(devs, 1);
        if (!dev) {
            fprintf(stderr, "No device found in Mi Assistant mode\n");
            return -1;
        }

        if (libusb_open(dev, &dev_handle) != LIBUSB_SUCCESS ||
            libusb_claim_interface(dev_handle, interface_num) != LIBUSB_SUCCESS) {
            fprintf(stderr, "Failed to open device or claim interface\n");
            return -1;
        }
    }
    return 0;
}

int connect_device() {
    char buf[512];
    AdbUsbPacket pkt;
    int data_len;
    if (send_command(ADB_CONNECT, ADB_VERSION, ADB_MAX_DATA, "host::\x0", 7) ||
        recv_packet(&pkt, buf, &data_len) ||
        memcmp(buf, "sideload::", 10)) {
        fprintf(stderr, "Failed to connect with device\n");
        return -1;
    }
    return 0;
}

int fetch_device_info(DeviceInfo *info) {
    char *response;
    response = adb_cmd("getdevice:");
    strncpy(info->device, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getversion:");
    strncpy(info->version, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getsn:");
    strncpy(info->sn, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getcodebase:");
    strncpy(info->codebase, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getbranch:");
    strncpy(info->branch, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getlanguage:");
    strncpy(info->language, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getregion:");
    strncpy(info->region, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    response = adb_cmd("getromzone:");
    strncpy(info->romzone, response ? response : "", MAX_STR_LEN - 1);
    free(response);

    return 0;
}

void print_device_info(const DeviceInfo *info) {
    printf("\n\nDevice: %s\nVersion: %s\nSerial Number: %s\nCodebase: %s\n"
           "Branch: %s\nLanguage: %s\nRegion: %s\nROM Zone: %s\n\n",
           info->device, info->version, info->sn, info->codebase,
           info->branch, info->language, info->region, info->romzone);
}

void cleanup_usb() {
    if (dev_handle) {
        if (interface_num != -1) {
            libusb_release_interface(dev_handle, interface_num);
        }
        libusb_close(dev_handle);
        dev_handle = NULL;
    }
    if (ctx) {
        libusb_exit(ctx);
        ctx = NULL;
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    int choice = atoi(argv[1]);
    if (choice < 1 || choice > 5) {
        fprintf(stderr, "Invalid choice\n");
        return 1;
    }

    int method = 2; // Default to root/Linux or Windows
#ifndef _WIN32
    if (getenv("PREFIX") && access("/data/data/com.termux", F_OK) != -1) {
        method = geteuid() == 0 ? 2 : 1;
    }
#endif

    if (initialize_usb(method, getenv("TERMUX_USB_FD"))) {
        cleanup_usb();
        return 1;
    }

    if (connect_device()) {
        cleanup_usb();
        return 1;
    }

    fetch_device_info(&global_device_info);

    switch (choice) {
        case 1:
            print_device_info(&global_device_info);
            break;
        case 2:
            validate_check("", 0);
            break;
        case 3: {
            char file_path[FILE_PATH_MAX], md5[MD5_LEN];
            if (get_zip_file_path(file_path, FILE_PATH_MAX) ||
                calculate_md5(file_path, md5)) {
                cleanup_usb();
                return 1;
            }
            const char *validate = validate_check(md5, 1);
            if (validate) {
                start_sideload(file_path, validate);
            }
            break;
        }
        case 4: {
            char *format = adb_cmd("format-data:");
            printf("\n%s\n", format ? format : "Failed to format data");
            free(format);
            char *reboot = adb_cmd("reboot:");
            printf("\n%s\n", reboot ? reboot : "Failed to reboot");
            free(reboot);
            break;
        }
        case 5: {
            char *reboot = adb_cmd("reboot:");
            printf("\n%s\n", reboot ? reboot : "Failed to reboot");
            free(reboot);
            break;
        }
    }

    cleanup_usb();
    return 0;
}
