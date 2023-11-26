#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_now.h"
#include "esp_now_pairing.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"

#define NVS_KEY "peer_config"

static const char *TAG = "esp_now_pairing";

esp_now_peer_config_t *g_pairing_peer_config;
esp_now_pairing_response_cb_t g_pairing_response_cb;

bool g_paired;

void espnow_pairing_data_received(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int data_len);

esp_err_t esp_now_pairing_write_config(esp_now_peer_config_t *peer_config);
esp_err_t esp_now_pairing_read_config(esp_now_peer_config_t *peer_config);

bool esp_now_pairing_init(esp_now_peer_config_t *peer_config)
{
    esp_err_t err = esp_now_pairing_read_config(peer_config);

    if (err == ESP_OK && peer_config->pairingCode != 0 && peer_config->channel != 0)
    {
        ESP_LOGI(TAG, "Peer config found: MAC = %02x:%02x:%02x:%02x:%02x:%02x, Channel = %d", MAC2STR(peer_config->macAddress), peer_config->channel);
        ESP_LOGI(TAG, "Product code: 0x%08lx", peer_config->pairingCode);
        ESP_LOGI(TAG, "Pairing code: 0x%08lx", peer_config->productCode);

        ESP_ERROR_CHECK(esp_wifi_set_channel(peer_config->channel, WIFI_SECOND_CHAN_NONE));

        esp_now_peer_info_t peerInfo;
        memset(&peerInfo, 0, sizeof(peerInfo));
        memcpy(peerInfo.peer_addr, peer_config->macAddress, ESP_NOW_ETH_ALEN);
        peerInfo.channel = 0;
        peerInfo.encrypt = false;

        ESP_ERROR_CHECK(esp_now_add_peer(&peerInfo));

        return true;
    }
    return false;
}

bool esp_now_pairing(TickType_t wait_ticks, esp_now_peer_config_t *peer_config, uint32_t clientProductCode, esp_now_pairing_response_cb_t response_cb, esp_now_pairing_scan_cb_t scan_cb )
{
    uint32_t start_ticks = xTaskGetTickCount();

    g_pairing_peer_config = peer_config;
    g_pairing_response_cb = response_cb;

    wifi_country_t country = {0};

    esp_wifi_get_country(&country);

    while (true)
    {
        for (int channel = 1; channel <= country.nchan; channel++)
        {
            if (wait_ticks != portMAX_DELAY && xTaskGetTickCount() - start_ticks > wait_ticks)
                return false;

            ESP_ERROR_CHECK(esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE));
            ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_pairing_data_received));

            esp_now_pairing_request_t pairing_request = {.magicWord = ESP_NOW_PAIRING_MAGICWORD, .productCode = clientProductCode};

            uint8_t serverAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

            esp_now_peer_info_t peerInfo;
            memset(&peerInfo, 0, sizeof(peerInfo));
            memcpy(peerInfo.peer_addr, serverAddress, ESP_NOW_ETH_ALEN);
            peerInfo.channel = 0;
            peerInfo.encrypt = false;

            ESP_LOGI(TAG, "Sending pairing request on channel %d", channel);

            ESP_ERROR_CHECK(esp_now_add_peer(&peerInfo));
            ESP_ERROR_CHECK(esp_now_send(serverAddress, (uint8_t *)&pairing_request, sizeof(pairing_request)));
            ESP_ERROR_CHECK(esp_now_del_peer(peerInfo.peer_addr));

            vTaskDelay(pdMS_TO_TICKS(100));

            if (g_paired)
                return true;

            if (scan_cb != NULL)
                scan_cb(channel);
        }
    }
    return false;
}

void espnow_pairing_data_received(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int data_len)
{
    if (data_len == sizeof(esp_now_pairing_response_t) && ((esp_now_pairing_response_t *)data)->magicWord == ESP_NOW_PAIRING_MAGICWORD)
    {
        esp_now_pairing_response_t *pairing_response = (esp_now_pairing_response_t *)data;

        if (g_pairing_response_cb == NULL || g_pairing_response_cb(pairing_response))
        {
            memcpy(g_pairing_peer_config->macAddress, esp_now_info->src_addr, sizeof(g_pairing_peer_config->macAddress));

            g_pairing_peer_config->pairingCode = pairing_response->pairingCode;
            g_pairing_peer_config->productCode = pairing_response->productCode;

            wifi_second_chan_t second_chan;

            ESP_ERROR_CHECK(esp_wifi_get_channel(&g_pairing_peer_config->channel, &second_chan));

            ESP_LOGI(TAG, "Pairing response from MAC = %02x:%02x:%02x:%02x:%02x:%02x, Channel = %d", MAC2STR(g_pairing_peer_config->macAddress),
                     g_pairing_peer_config->channel);
            ESP_LOGI(TAG, "Product code: 0x%08lx", g_pairing_peer_config->pairingCode);
            ESP_LOGI(TAG, "Pairing code: 0x%08lx", g_pairing_peer_config->productCode);

            esp_now_peer_info_t peerInfo;
            memset(&peerInfo, 0, sizeof(peerInfo));
            memcpy(peerInfo.peer_addr, g_pairing_peer_config->macAddress, ESP_NOW_ETH_ALEN);
            peerInfo.channel = 0;
            peerInfo.encrypt = false;

            ESP_ERROR_CHECK_WITHOUT_ABORT(esp_now_add_peer(&peerInfo));
            ESP_ERROR_CHECK(esp_now_unregister_recv_cb());

            ESP_ERROR_CHECK(esp_now_pairing_write_config(g_pairing_peer_config));

            g_paired = true;
        }
        else
        {
            ESP_LOGV(TAG, "Pairing rejected by response callback");
        }
    }
}

bool esp_now_pairing_handler(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int data_len, uint32_t pairingCode, uint32_t serverProductCode,
                            esp_now_pairing_request_cb_t cb)
{
    if (data_len == sizeof(esp_now_pairing_request_t) && ((esp_now_pairing_request_t *)data)->magicWord == ESP_NOW_PAIRING_MAGICWORD)
    {
        esp_now_pairing_request_t *pairing_request = (esp_now_pairing_request_t *)data;

        esp_now_pairing_response_t pairing_response = {
            .magicWord = ESP_NOW_PAIRING_MAGICWORD, .pairingCode = (uint32_t)pairingCode, .productCode = serverProductCode};

        ESP_LOGI(TAG, "Pairing request to %02x:%02x:%02x:%02x:%02x:%02x from MAC %02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(esp_now_info->des_addr),
                 MAC2STR(esp_now_info->src_addr));

        if (cb == NULL || cb(pairing_request))
        {
            esp_now_peer_info_t peerInfo;
            memset(&peerInfo, 0, sizeof(peerInfo));
            memcpy(peerInfo.peer_addr, esp_now_info->src_addr, ESP_NOW_ETH_ALEN);
            peerInfo.channel = 0;
            peerInfo.encrypt = false;

            // Add peer so we can send a message
            esp_now_add_peer(&peerInfo);

            // Send pairing response
            esp_now_send(esp_now_info->src_addr, (uint8_t *)&pairing_response, sizeof(pairing_response));

            // Remove peer once message has been sent
            esp_now_del_peer(esp_now_info->src_addr);

            return true;
        }
        else
        {
            ESP_LOGI(TAG, "Pairing rejected by request callback");
        }
    }
    return false;
}

esp_err_t esp_now_pairing_write_config(esp_now_peer_config_t *peer_config)
{
    nvs_handle_t handle;
    esp_err_t err;

    err = nvs_open(TAG, NVS_READWRITE, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_set_blob(handle, NVS_KEY, peer_config, sizeof(esp_now_peer_config_t));
    if (err != ESP_OK)
    {
        nvs_close(handle);
        return err;
    }

    err = nvs_commit(handle);

    nvs_close(handle);
    return err;
}

esp_err_t esp_now_pairing_read_config(esp_now_peer_config_t *peer_config)
{
    nvs_handle_t handle;
    esp_err_t err;
    err = nvs_open(TAG, NVS_READWRITE, &handle);
    if (err != ESP_OK)
        return err;

    size_t size = sizeof(esp_now_peer_config_t);

    err = nvs_get_blob(handle, NVS_KEY, peer_config, &size);

    nvs_close(handle);
    return err;
}