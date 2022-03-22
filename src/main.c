#include <stdio.h>

#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#define GPIO_BUILTIN_LED 5

void app_main(void) {
  gpio_pad_select_gpio(GPIO_BUILTIN_LED);
  gpio_set_direction(GPIO_BUILTIN_LED, GPIO_MODE_OUTPUT);

  while (true) {
    printf("Turning off the LED\n");
    gpio_set_level(GPIO_BUILTIN_LED, 0);
    vTaskDelay(300 / portTICK_PERIOD_MS);

    printf("Turningn on the LED\n");
    gpio_set_level(GPIO_BUILTIN_LED, 1);
    vTaskDelay(300 / portTICK_PERIOD_MS);
  }
}
