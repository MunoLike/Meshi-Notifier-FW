/**
 * WIFI Sniffer(Monitor) feature was based on below page.
 * https://blog.podkalicki.com/esp32-wifi-sniffer/
 *
 * http-request function was based on below page.
 * https://github.com/espressif/esp-idf/blob/9763125c1c4aaec8fb6c85d97abb52ccb72066c9/examples/protocols/esp_http_client/main/esp_http_client_example.c
 *
 * @MunoLike 2022-04
 */

#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "nvs_flash.h"

//see LOLIN D32 specification sheet.
#define LED_GPIO_PIN GPIO_NUM_5
#define STATLED_MONITOR_INTERVAL (500)
#define EXAMPLE_ESP_MAXIMUM_RETRY (3)

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

#define MODE_MONITOR (0)
#define MODE_REQUEST (1)

#define KEY_MODE "currentMode"

const char *TAG = "MAIN";

typedef struct {
  unsigned frame_ctrl : 16;
  unsigned duration_id : 16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static void wifi_sniffer_init(void);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

int s_retry_num = 0;

static EventGroupHandle_t s_wifi_event_group;

static nvs_handle nvsHandle;

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
      esp_wifi_connect();
      s_retry_num++;
      ESP_LOGI(TAG, "retry to connect to the AP");
    } else {
      xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    }
    ESP_LOGI(TAG, "connect to the AP fail");
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
    s_retry_num = 0;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
  }
}

void wifi_sta_init() {
  s_wifi_event_group = xEventGroupCreate();
  ESP_ERROR_CHECK(esp_netif_init());

  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  esp_event_handler_instance_t instance_any_id;
  esp_event_handler_instance_t instance_got_ip;
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

//TODO: You should define below variables.
  wifi_config_t wifi_config = {
      .sta = {
          .ssid = "",
          .password = "",
          /* Setting a password implies station will connect to all security modes including WEP/WPA.
           * However these modes are deprecated and not advisable to be used. Incase your Access point
           * doesn't support WPA2, these mode can be enabled by commenting below line */
          .threshold.authmode = WIFI_AUTH_WPA2_PSK,
      },
  };
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "wifi_init_sta finished.");

  EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                         pdFALSE,
                                         pdFALSE,
                                         portMAX_DELAY);

  if (bits & WIFI_CONNECTED_BIT) {
    ESP_LOGI(TAG, "connected to ap SSID: password:");
  } else if (bits & WIFI_FAIL_BIT) {
    ESP_LOGI(TAG, "Failed to connect to SSID: , password:");
  } else {
    ESP_LOGE(TAG, "UNEXPECTED EVENT");
  }
}

// I've never used the responce data.
void http_request() {
  esp_http_client_config_t config = {
      .host = "meshi-notifier.herokuapp.com",
      .path = "/call",
      .disable_auto_redirect = true};

  esp_http_client_handle_t client = esp_http_client_init(&config);

  esp_http_client_set_method(client, HTTP_METHOD_POST);
  esp_http_client_set_header(client, "Content-Type", "application/json");
  //My original API-TOKEN(censored)
  esp_http_client_set_header(client, "id", "");
  ESP_ERROR_CHECK(esp_http_client_perform(client));
  ESP_LOGI(TAG, "REQ HAS BEEN DONE.");
}

void switch_mode(uint8_t mode) {
  nvs_set_u8(nvsHandle, KEY_MODE, mode);
  nvs_commit(nvsHandle);
  nvs_close(nvsHandle);
  esp_restart();
}

void wifi_sniffer_init(void) {
  esp_netif_init();
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  wifi_country_t wifi_country = {.cc = "JP", .schan = 1, .nchan = 1, .policy = WIFI_COUNTRY_POLICY_AUTO};
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt =
      (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  if (ipkt->hdr.addr2[0] == 0xb4 && ipkt->hdr.addr2[1] == 0x7c &&
      ipkt->hdr.addr2[2] == 0x9c && ipkt->hdr.addr2[3] == 0xae &&
      ipkt->hdr.addr2[4] == 0xad && ipkt->hdr.addr2[5] == 0xe7) {
    printf("Receive Packet!!\n");
    switch_mode(MODE_REQUEST);
  }
}

void app_main(void) {
  uint8_t level = 0;

  /* setup */
  nvs_flash_init();
  ESP_ERROR_CHECK(nvs_open("meshi", NVS_READWRITE, &nvsHandle));

  uint8_t mode = 0;
  ESP_ERROR_CHECK(nvs_get_u8(nvsHandle, KEY_MODE, &mode));

  if (mode == MODE_MONITOR) {
    /*Monitor Mode*/
    wifi_sniffer_init();
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);  // static and const.
    gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);
    /*loop */
    while (true) {
      gpio_set_level(LED_GPIO_PIN, level ^= 1);
      vTaskDelay(STATLED_MONITOR_INTERVAL / portTICK_PERIOD_MS);
    }
  } else if (mode == MODE_REQUEST) {
    /*STA Mode*/
    wifi_sta_init();
    http_request();
    vTaskDelay(5000 / portTICK_PERIOD_MS);
    switch_mode(MODE_MONITOR);
  }
}