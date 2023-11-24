idf_component_register(SRCS "esp_now_pairing.c"
                  REQUIRES nvs_flash esp_wifi 
                    INCLUDE_DIRS "include")
