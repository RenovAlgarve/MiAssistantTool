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

#define VERSION "1.2"
#define REPOSITORY "https://github.com/offici5l/MiAssistantTool"
#define MIUI_UPDATE_URL "http://update.miui.com/updates/miotaV3.php"
#define MIUI_USER_AGENT "MiTunes_UserAgent_v3.0"
#define ADB_SIDELOAD_CHUNK_SIZE (1024 * 64) // 64KB chunks

// Error codes
#define ERR_SUCCESS 0
#define ERR_USB_READ -1
#define ERR_USB_WRITE -2
#define ERR_FILE_OPEN -3
#define ERR_MEMORY_ALLOC -4
#define ERR_CURL_INIT -5
#define ERR_ENCRYPTION -6
#define ERR_DECRYPTION -7
#define ERR_JSON_PARSE -8
#define ERR_INVALID_CHOICE -9
#define ERR_DEVICE_NOT_FOUND -10
#define ERR_ADB_COMMAND -11

// Constants
static const unsigned char AES_KEY[16] = {0x6D, 0x69, 0x75, 0x69, 0x6F, 0x74, 0x61, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x65, 0x64, 0x31, 0x31};
static const unsigned char AES_IV[16] = {0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38};

// Device context to encapsulate global state
typedef struct {
    char device[80];
    char version[80];
    char sn[80];
    char codebase[80];
    char branch[80];
    char language[80];
    char region[80];
    char romzone[80];
    int bulk_in;
    int bulk_out;
    int interface_num;
    libusb_context *ctx;
    libusb_device_handle *dev_handle;
    char response[4096];
} DeviceContext;

// ADB packet structure
typedef struct {
    uint32_t cmd;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t len;
    uint32_t checksum;
    uint32_t magic;
} adb_usb_packet;

// Function prototypes
int init_device_context(DeviceContext *ctx);
void cleanup_device_context(DeviceContext *ctx);
int usb_read(DeviceContext *ctx, void *data, int datalen, int *read_len);
int usb_write(DeviceContext *ctx, void *data, int datalen, int *write_len);
int send_command(DeviceContext *ctx, uint32_t cmd, uint32_t arg0, uint32_t arg1, void *data, int datalen);
int recv_packet(DeviceContext *ctx, adb_usb_packet *pkt, void *data, int *data_len);
char* adb_cmd(DeviceContext *ctx, const char *command);
int calculate_md5(const char *prompt, char *filePath, size_t filePathLen, char *md5, size_t md5Len);
int encrypt_json_request(const char *json_request, unsigned char *encrypted_data, int *encrypted_len);
int decrypt_response(const unsigned char *encrypted_data, int encrypted_len, char *decrypted_data, int *decrypted_len);
const char* validate_check(DeviceContext *ctx, const char *md5, int flash);
int start_sideload(DeviceContext *ctx, const char *sideload_file, const char *validate);
int check_device(libusb_device *dev, int *bulk_in, int *bulk_out, int *interface_num);
int handle_read_info(DeviceContext *ctx);
int handle_list_roms(DeviceContext *ctx);
int handle_flash_rom(DeviceContext *ctx);
int handle_format_data(DeviceContext *ctx);
int handle_reboot(DeviceContext *ctx);

// Initialize device context
int init_device_context(DeviceContext *ctx) {
    memset(ctx, 0, sizeof(DeviceContext));
    int r = libusb_init(&ctx->ctx);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "Failed to initialize libusb: %s\n", libusb_error_name(r));
        return -1;
    }
    libusb_set_option(ctx->ctx, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    return ERR_SUCCESS;
}

// Cleanup device context
void cleanup_device_context(DeviceContext *ctx) {
    if (ctx->dev_handle) {
        libusb_release_interface(ctx->dev_handle, ctx->interface_num);
        libusb_close(ctx->dev_handle);
    }
    if (ctx->ctx) {
        libusb_exit(ctx->ctx);
    }
    memset(ctx, 0, sizeof(DeviceContext));
}

// USB read with error handling
int usb_read(DeviceContext *ctx, void *data, int datalen, int *read_len) {
    int r = libusb_bulk_transfer(ctx->dev_handle, ctx->bulk_in, data, datalen, read_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "USB read failed: %s\n", libusb_error_name(r));
        return ERR_USB_READ;
    }
    return ERR_SUCCESS;
}

// USB write with error handling
int usb_write(DeviceContext *ctx, void *data, int datalen, int *write_len) {
    int r = libusb_bulk_transfer(ctx->dev_handle, ctx->bulk_out, data, datalen, write_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "USB write failed: %s\n", libusb_error_name(r));
        return ERR_USB_WRITE;
    }
    return ERR_SUCCESS;
}

// Send ADB command
int send_command(DeviceContext *ctx, uint32_t cmd, uint32_t arg0, uint32_t arg1, void *data, int datalen) {
    adb_usb_packet pkt = {
        .cmd = cmd,
        .arg0 = arg0,
        .arg1 = arg1,
        .len = datalen,
        .checksum = 0,
        .magic = cmd ^ 0xffffffff
    };
    int write_len;
    if (usb_write(ctx, &pkt, sizeof(pkt), &write_len) != ERR_SUCCESS || write_len != sizeof(pkt)) {
        return -1;
    }
    if (datalen > 0) {
        if (usb_write(ctx, data, datalen, &write_len) != ERR_SUCCESS || write_len != datalen) {
            return -1;
        }
    }
    return ERR_SUCCESS;
}

// Receive ADB packet
int recv_packet(DeviceContext *ctx, adb_usb_packet *pkt, void *data, int *data_len) {
    int read_len;
    if (usb_read(ctx, pkt, sizeof(adb_usb_packet), &read_len) != ERR_SUCCESS || read_len != sizeof(adb_usb_packet)) {
        return -1;
    }
    if (pkt->len > 0) {
        if (usb_read(ctx, data, pkt->len, &read_len) != ERR_SUCCESS || read_len != (int)pkt->len) {
            return -1;
        }
    }
    *data_len = pkt->len;
    return ERR_SUCCESS;
}

// Execute ADB command and store response
char* adb_cmd(DeviceContext *ctx, const char *command) {
    int cmd_len = strlen(command);
    if (send_command(ctx, ADB_OPEN, 1, 0, (void *)command, cmd_len + 1) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to send ADB command: %s\n", command);
        return NULL;
    }
    adb_usb_packet pkt;
    char data[512];
    int data_len;
    if (recv_packet(ctx, &pkt, data, &data_len) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to receive ADB packet\n");
        return NULL;
    }
    if (recv_packet(ctx, &pkt, ctx->response, &data_len) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to receive response\n");
        return NULL;
    }
    ctx->response[data_len] = '\0';
    if (data_len > 0 && ctx->response[data_len - 1] == '\n') {
        ctx->response[data_len - 1] = '\0';
    }
    return ctx->response;
}

// Calculate MD5 of a file
int calculate_md5(const char *prompt, char *filePath, size_t filePathLen, char *md5, size_t md5Len) {
    FILE *file = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char data[1024], md5hash[EVP_MAX_MD_SIZE];
    unsigned int md5len;

    while (1) {
        printf("%s", prompt);
        if (!fgets(filePath, filePathLen, stdin)) {
            fprintf(stderr, "Failed to read file path\n");
            return ERR_FILE_OPEN;
        }
        filePath[strcspn(filePath, "\n")] = '\0';
        if (strstr(filePath, ".zip") && (file = fopen(filePath, "rb"))) {
            break;
        }
        printf("Invalid file, try again.\n");
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        fprintf(stderr, "Failed to initialize MD5 context\n");
        if (file) fclose(file);
        return ERR_ENCRYPTION;
    }

    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, data, bytesRead) != 1) {
            fprintf(stderr, "Failed to update MD5\n");
            goto cleanup;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, md5hash, &md5len) != 1) {
        fprintf(stderr, "Failed to finalize MD5\n");
        goto cleanup;
    }

    for (unsigned int i = 0; i < md5len; i++) {
        snprintf(&md5[i * 2], md5Len - i * 2, "%02x", md5hash[i]);
    }
    md5[md5len * 2] = '\0';

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (file) fclose(file);
    return md5len > 0 ? ERR_SUCCESS : ERR_ENCRYPTION;
}

// Encrypt JSON request
int encrypt_json_request(const char *json_request, unsigned char *encrypted_data, int *encrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ERR_ENCRYPTION;

    int len = strlen(json_request);
    int mod_len = 16 - (len % 16);
    char padded_request[1024];
    memcpy(padded_request, json_request, len);
    if (mod_len > 0) memset(padded_request + len, mod_len, mod_len);
    len += mod_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, AES_KEY, AES_IV) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted_data, encrypted_len, (unsigned char *)padded_request, len) != 1 ||
        EVP_EncryptFinal_ex(ctx, encrypted_data + *encrypted_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ERR_ENCRYPTION;
    }
    *encrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ERR_SUCCESS;
}

// Decrypt response
int decrypt_response(const unsigned char *encrypted_data, int encrypted_len, char *decrypted_data, int *decrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ERR_DECRYPTION;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, AES_KEY, AES_IV) != 1 ||
        EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_data, decrypted_len, encrypted_data, encrypted_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_data + *decrypted_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ERR_DECRYPTION;
    }
    *decrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ERR_SUCCESS;
}

// Validate ROM or list ROMs
const char* validate_check(DeviceContext *ctx, const char *md5, int flash) {
    CURL *curl = NULL;
    char *json_post_data = NULL;
    unsigned char *post_buf = NULL;
    char *response_buffer = NULL;
    FILE *response_file = NULL;
    const char *result = NULL;

    char json_request[1024];
    unsigned char encrypted_data[1024];
    int encrypted_len = 0;
    char decrypted_data[1024];
    int decrypted_len = 0;

    snprintf(json_request, sizeof(json_request),
             "{\"d\":\"%s\",\"v\":\"%s\",\"c\":\"%s\",\"b\":\"%s\",\"sn\":\"%s\",\"l\":\"en-US\",\"f\":\"1\",\"options\":{\"zone\":%s},\"pkg\":\"%s\"}",
             ctx->device, ctx->version, ctx->codebase, ctx->branch, ctx->sn, ctx->romzone, md5);

    if (encrypt_json_request(json_request, encrypted_data, &encrypted_len) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to encrypt JSON request\n");
        goto cleanup;
    }

    char encoded_buf[EVP_ENCODE_LENGTH(encrypted_len)];
    EVP_EncodeBlock((unsigned char *)encoded_buf, encrypted_data, encrypted_len);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize cURL\n");
        goto cleanup;
    }

    json_post_data = curl_easy_escape(curl, encoded_buf, strlen(encoded_buf));
    if (!json_post_data) {
        fprintf(stderr, "Failed to escape JSON post data\n");
        goto cleanup;
    }

    size_t post_buf_len = strlen(json_post_data) + 10;
    post_buf = malloc(post_buf_len);
    if (!post_buf) {
        fprintf(stderr, "Failed to allocate post_buf\n");
        goto cleanup;
    }
    snprintf((char *)post_buf, post_buf_len, "q=%s&t=&s=1", json_post_data);

    response_file = fopen("response.tmp", "wb");
    if (!response_file) {
        perror("Error opening file for writing");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, MIUI_UPDATE_URL);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, MIUI_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_file);

    if (curl_easy_perform(curl) != CURLE_OK) {
        perror("Error during curl_easy_perform");
        goto cleanup;
    }
    fclose(response_file);
    response_file = NULL;

    response_file = fopen("response.tmp", "rb");
    if (!response_file) {
        perror("Failed to open file for reading");
        goto cleanup;
    }

    fseek(response_file, 0, SEEK_END);
    long response_size = ftell(response_file);
    fseek(response_file, 0, SEEK_SET);

    response_buffer = malloc(response_size + 1);
    if (!response_buffer) {
        perror("Memory allocation failed");
        goto cleanup;
    }

    fread(response_buffer, 1, response_size, response_file);
    response_buffer[response_size] = '\0';

    unsigned char decoded_data[1024];
    int decoded_len = EVP_DecodeBlock(decoded_data, (unsigned char *)response_buffer, response_size);

    if (decrypt_response(decoded_data, decoded_len, decrypted_data, &decrypted_len) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to decrypt response\n");
        goto cleanup;
    }

    json_t pool[10000];
    json_t const *parsed_json = json_create(decrypted_data, pool, 10000);
    if (!parsed_json) {
        fprintf(stderr, "Failed to parse JSON\n");
        goto cleanup;
    }

    if (flash == 1) {
        json_t const *pkg_rom = json_getProperty(parsed_json, "PkgRom");
        if (pkg_rom) {
            int Erase = atoi(json_getValue(json_getProperty(pkg_rom, "Erase")));
            if (Erase == 1) {
                printf("NOTICE: Data will be erased during flashing.\nPress Enter to continue...");
                getchar();
            }
            json_t const *validate = json_getProperty(pkg_rom, "Validate");
            result = json_getValue(validate);
        } else {
            json_t const *code = json_getProperty(parsed_json, "Code");
            json_t const *message = json_getProperty(code, "message");
            printf("\n%s\n", json_getValue(message));
        }
    } else {
        printf("Available ROMs:\n");
        if (json_getType(parsed_json) == JSON_OBJ) {
            json_t const *child = json_getChild(parsed_json);
            if (strcmp(json_getName(json_getSibling(child)), "Signup") == 0 || strcmp(json_getName(json_getSibling(child)), "VersionBoot") == 0) {
                fprintf(stderr, "Error: Invalid data\n");
                return NULL;
            }
            while (child) {
                child = json_getSibling(child); 
                if (strcmp(json_getName(child), "Icon") == 0) {
                    break;
                }
                json_t const *cA = json_getProperty(parsed_json, json_getName(child));
                if (cA) {
                    json_t const *md5 = json_getProperty(cA, "md5");
                    if (md5) {
                        printf("\n%s: %s\nmd5: %s\n", json_getName(child), json_getValue(json_getProperty(cA, "name")), json_getValue(md5));
                    } 
                }     
            }
        }
        return NULL;
    }

cleanup:
    if (response_file) fclose(response_file);
    if (response_buffer) free(response_buffer);
    if (json_post_data) curl_free(json_post_data);
    if (post_buf) free(post_buf);
    if (curl) curl_easy_cleanup(curl);
    return result;
}

// remove("response.tmp"); 

// Start sideload process
int start_sideload(DeviceContext *ctx, const char *sideload_file, const char *validate) {
    FILE *fp = fopen(sideload_file, "rb");
    if (!fp) {
        perror("Failed to open file");
        return ERR_FILE_OPEN;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char sideload_host_command[128];
    snprintf(sideload_host_command, sizeof(sideload_host_command), "sideload-host:%ld:%d:%s:0", file_size, ADB_SIDELOAD_CHUNK_SIZE, validate);

    if (send_command(ctx, ADB_OPEN, 1, 0, sideload_host_command, strlen(sideload_host_command) + 1) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to send sideload command\n");
        fclose(fp);
        return ERR_ADB_COMMAND;
    }

    uint8_t *work_buffer = malloc(ADB_SIDELOAD_CHUNK_SIZE);
    if (!work_buffer) {
        perror("Failed to allocate memory");
        fclose(fp);
        return ERR_MEMORY_ALLOC;
    }

    adb_usb_packet pkt;
    char dummy_data[64];
    int dummy_data_size;
    long total_sent = 0;

    while (1) {
        if (recv_packet(ctx, &pkt, dummy_data, &dummy_data_size) != ERR_SUCCESS) {
            fprintf(stderr, "Failed to receive packet\n");
            break;
        }
        dummy_data[dummy_data_size] = '\0';

        if (pkt.cmd == ADB_OKAY) {
            send_command(ctx, ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0);
        } else if (pkt.cmd == ADB_WRTE) {
            long block = strtol(dummy_data, NULL, 10);
            long offset = block * ADB_SIDELOAD_CHUNK_SIZE;
            if (offset >= file_size) break;
            int to_write = (offset + ADB_SIDELOAD_CHUNK_SIZE > file_size) ? file_size - offset : ADB_SIDELOAD_CHUNK_SIZE;
            fseek(fp, offset, SEEK_SET);
            fread(work_buffer, 1, to_write, fp);
            send_command(ctx, ADB_WRTE, pkt.arg1, pkt.arg0, work_buffer, to_write);
            send_command(ctx, ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0);
            total_sent += to_write;
            printf("\rFlashing in progress ... %d%%", (int)(total_sent * 100 / file_size));
            fflush(stdout);
        }
    }

    free(work_buffer);
    fclose(fp);
    return ERR_SUCCESS;
}

// Check device in ADB mode
int check_device(libusb_device *dev, int *bulk_in, int *bulk_out, int *interface_num) {
    struct libusb_device_descriptor desc;
    int r = libusb_get_device_descriptor(dev, &desc);
    if (r != LIBUSB_SUCCESS) return -1;

    struct libusb_config_descriptor *configs;
    r = libusb_get_active_config_descriptor(dev, &configs);
    if (r != LIBUSB_SUCCESS) return -1;

    *bulk_in = -1;
    *bulk_out = -1;
    *interface_num = -1;

    for (int i = 0; i < configs->bNumInterfaces; i++) {
        struct libusb_interface intf = configs->interface[i];
        if (intf.num_altsetting == 0) continue;
        *interface_num = i;
        struct libusb_interface_descriptor intf_desc = intf.altsetting[0];
        if (intf_desc.bInterfaceClass == ADB_CLASS && intf_desc.bInterfaceSubClass == ADB_SUB_CLASS && intf_desc.bInterfaceProtocol == ADB_PROTOCOL_CODE) {
            for (int endpoint_num = 0; endpoint_num < intf_desc.bNumEndpoints; endpoint_num++) {
                struct libusb_endpoint_descriptor ep = intf_desc.endpoint[endpoint_num];
                if ((ep.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_BULK) {
                    if ((ep.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
                        *bulk_out = ep.bEndpointAddress;
                    } else {
                        *bulk_in = ep.bEndpointAddress;
                    }
                }
                if (*bulk_out != -1 && *bulk_in != -1) {
                    libusb_free_config_descriptor(configs);
                    return ERR_SUCCESS;
                }
            }
        }
    }
    libusb_free_config_descriptor(configs);
    return ERR_DEVICE_NOT_FOUND;
}

// Command handlers
int handle_read_info(DeviceContext *ctx) {
    printf("\n\nDevice: %s\n", ctx->device);
    printf("Version: %s\n", ctx->version);
    printf("Serial Number: %s\n", ctx->sn);
    printf("Codebase: %s\n", ctx->codebase);
    printf("Branch: %s\n", ctx->branch);
    printf("Language: %s\n", ctx->language);
    printf("Region: %s\n", ctx->region);
    printf("ROM Zone: %s\n\n", ctx->romzone);
    return ERR_SUCCESS;
}

int handle_list_roms(DeviceContext *ctx) {
    validate_check(ctx, "", 0);
    return ERR_SUCCESS;
}

int handle_flash_rom(DeviceContext *ctx) {
    char filePath[256], md5[65];
    if (calculate_md5("Enter .zip file path: ", filePath, sizeof(filePath), md5, sizeof(md5)) != ERR_SUCCESS) {
        return -1;
    }
    const char *validate = validate_check(ctx, md5, 1);
    if (validate) {
        return start_sideload(ctx, filePath, validate);
    }
    return -1;
}

int handle_format_data(DeviceContext *ctx) {
    char *format = adb_cmd(ctx, "format-data:");
    if (format) printf("\n%s\n", format);
    char *reboot = adb_cmd(ctx, "reboot:");
    if (reboot) printf("\n%s\n", reboot);
    return ERR_SUCCESS;
}

int handle_reboot(DeviceContext *ctx) {
    char *reboot = adb_cmd(ctx, "reboot:");
    if (reboot) printf("\n%s\n", reboot);
    return ERR_SUCCESS;
}

// Main function
int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("\nVERSION: %s\nRepository: %s\n\n", VERSION, REPOSITORY);
        printf("Usage: %s \033[0;32m<choice>\033[0m\n\n  \033[0;32mchoice\033[0m > description\n\n", argv[0]);
        const char *choices[] = {"Read Info", "ROMs that can be flashed", "Flash Official Recovery ROM", "Format Data", "Reboot"};
        for (int i = 0; i < 5; i++) {
            printf("  \033[0;32m%d\033[0m > %s\n\n", i + 1, choices[i]);
        }
        return 0;
    }

    int choice = atoi(argv[1]);
    if (choice < 1 || choice > 5) {
        fprintf(stderr, "Invalid choice\n");
        return ERR_INVALID_CHOICE;
    }

    DeviceContext ctx;
    if (init_device_context(&ctx) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to initialize device context\n");
        return -1;
    }

    const char *fd = getenv("TERMUX_USB_FD");
    if (fd == NULL) {
        fprintf(stderr, "\n\nWithout root (termux-usb must be used)\n\n");
        cleanup_device_context(&ctx);
        return -1;
    }

    int r = libusb_wrap_sys_device(ctx.ctx, (intptr_t)atoi(fd), &ctx.dev_handle);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "Failed to open device: %s\n", libusb_error_name(r));
        cleanup_device_context(&ctx);
        return -1;
    }

    if (check_device(libusb_get_device(ctx.dev_handle), &ctx.bulk_in, &ctx.bulk_out, &ctx.interface_num) != ERR_SUCCESS) {
        fprintf(stderr, "\n\ndevice is not connected, or not in mi assistant mode\n\n");
        cleanup_device_context(&ctx);
        return ERR_DEVICE_NOT_FOUND;
    }

    r = libusb_claim_interface(ctx.dev_handle, ctx.interface_num);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "Failed to claim interface: %s\n", libusb_error_name(r));
        cleanup_device_context(&ctx);
        return -1;
    }

    if (send_command(&ctx, ADB_CONNECT, ADB_VERSION, ADB_MAX_DATA, "host::\x0", 7) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to send ADB connect\n");
        cleanup_device_context(&ctx);
        return -1;
    }

    adb_usb_packet pkt;
    char buf[512];
    int data_len;
    if (recv_packet(&ctx, &pkt, buf, &data_len) != ERR_SUCCESS || memcmp(buf, "sideload::", 10)) {
        fprintf(stderr, "Failed to connect with device\n");
        cleanup_device_context(&ctx);
        return -1;
    }

    strncpy(ctx.device, adb_cmd(&ctx, "getdevice:"), sizeof(ctx.device) - 1);
    strncpy(ctx.version, adb_cmd(&ctx, "getversion:"), sizeof(ctx.version) - 1);
    strncpy(ctx.sn, adb_cmd(&ctx, "getsn:"), sizeof(ctx.sn) - 1);
    strncpy(ctx.codebase, adb_cmd(&ctx, "getcodebase:"), sizeof(ctx.codebase) - 1);
    strncpy(ctx.branch, adb_cmd(&ctx, "getbranch:"), sizeof(ctx.branch) - 1);
    strncpy(ctx.language, adb_cmd(&ctx, "getlanguage:"), sizeof(ctx.language) - 1);
    strncpy(ctx.region, adb_cmd(&ctx, "getregion:"), sizeof(ctx.region) - 1);
    strncpy(ctx.romzone, adb_cmd(&ctx, "getromzone:"), sizeof(ctx.romzone) - 1);

    int (*handlers[])(DeviceContext *) = {
        handle_read_info,
        handle_list_roms,
        handle_flash_rom,
        handle_format_data,
        handle_reboot
    };

    if (handlers[choice - 1](&ctx) != ERR_SUCCESS) {
        fprintf(stderr, "Command failed\n");
        cleanup_device_context(&ctx);
        return -1;
    }

    cleanup_device_context(&ctx);
    return 0;
}
