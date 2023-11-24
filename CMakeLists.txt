idf_component_register(SRCS "esp_now_pairing.cpp"
                  REQUIRES nvs_flash esp_now 
                    INCLUDE_DIRS "include")
