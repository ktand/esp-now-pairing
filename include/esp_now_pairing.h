#ifndef __ESP_NOW_PAIRING_H__
#define __ESP_NOW_PAIRING_H__

#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ESP_NOW_PAIRING_MAGICWORD 0xf1a2f9ca
#define ESP_NOW_PING_MAGICWORD 0x7423af32

    typedef struct
    {
        uint32_t magicWord;   // Pairing magic word. Must match between client and server
        uint32_t productCode; // Client product code. Server can choose to accept the product code or not
    } esp_now_pairing_request_t;

    typedef struct
    {
        uint32_t magicWord;   // Pairing magic word. Must match between client and server
        uint32_t pairingCode; // Pairing code. Server can require this pairing code to be verified when a data packet is received
        uint32_t productCode; // Server product code. Client can choose to accept pairing and handle different scenarios based on the product code
    } esp_now_pairing_response_t;

    typedef struct
    {
        uint32_t magicWord;
    } esp_now_ping_request_t;

    typedef struct
    {
        uint8_t macAddress[6]; // Server mac address
        uint8_t channel;       // Server channel
        uint32_t pairingCode;  // Pairing code. Server can require this pairing code to be verified when a data packet is received
        uint32_t productCode;  // Server product code. Client can choose to accept pairing and handle different scenarios based on the product code
    } esp_now_peer_config_t;

    typedef bool (*esp_now_pairing_request_cb_t)(esp_now_pairing_request_t *pairing_request);
    typedef void (*esp_now_pairing_scan_cb_t)(uint8_t channel);
    typedef bool (*esp_now_pairing_response_cb_t)(esp_now_pairing_response_t *pairing_response);

    bool esp_now_pairing_init(esp_now_peer_config_t *peer_config);
    bool esp_now_pairing(TickType_t wait_ticks, esp_now_peer_config_t *peer_config, uint32_t clientProductCode, esp_now_pairing_response_cb_t response_cb, esp_now_pairing_scan_cb_t scan_cb);
    bool esp_now_pairing_handler(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int data_len, uint32_t pairingCode, uint32_t serverProductCode,
                                 esp_now_pairing_request_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif
